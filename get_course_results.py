#!/usr/bin/env python3

import requests
from bs4 import BeautifulSoup
import sys
import getpass
import urllib3
import os
import re
from urllib.parse import unquote
import argparse
import configparser
import time

# --- Helper Function ---
def sanitize_filename(name):
    """Removes characters invalid for filenames, keeping spaces."""
    if not name: return "untitled"
    name = re.sub(r'[\\/*?:"<>|]', '', name) # Remove invalid chars
    name = name.strip('. ')
    return name if name else "untitled"

# --- Config File Handling ---
config_file = 'config.ini'
config = configparser.ConfigParser(interpolation=None)
moodle_base_url = None
config_username = None
config_password = None
login_path = '/login/index.php'
course_view_path = '/course/view.php'
grade_export_setup_path = '/grade/export/xls/index.php'
grade_export_post_path = '/grade/export/xls/export.php'
quiz_download_path = '/mod/quiz/report.php'
base_results_dir = '.'
verify_ssl = False
request_delay = 0.0

if os.path.exists(config_file):
    try:
        config.read(config_file)
        print(f"[*] Reading configuration from '{config_file}'")

        # Read Moodle Config (optional now)
        moodle_base_url = config.get('Moodle', 'base_url', fallback=None)
        config_username = config.get('Moodle', 'username', fallback=None)
        config_password = config.get('Moodle', 'password', fallback=None)

        # Read Paths Config (with defaults)
        login_path = config.get('Paths', 'login_path', fallback=login_path)
        course_view_path = config.get('Paths', 'course_view_path', fallback=course_view_path)
        grade_export_setup_path = config.get('Paths', 'grade_export_setup_path', fallback=grade_export_setup_path)
        grade_export_post_path = config.get('Paths', 'grade_export_post_path', fallback=grade_export_post_path)
        quiz_download_path = config.get('Paths', 'quiz_download_path', fallback=quiz_download_path)
        base_results_dir = config.get('Paths', 'results_base_dir', fallback=base_results_dir)

        # Read Settings Config
        verify_ssl = config.getboolean('Settings', 'verify_ssl', fallback=verify_ssl)
        request_delay = config.getfloat('Settings', 'request_delay_seconds', fallback=request_delay)

    except configparser.Error as e:
        print(f"[!] Warning: Error reading configuration file '{config_file}': {e}")
        print("      Will proceed by prompting for missing values.")

        moodle_base_url = None
        config_username = None
        config_password = None
else:
    print(f"[!] Warning: Configuration file '{config_file}' not found.")
    print("      Will proceed by prompting for required values.")

# --- Prompt for Base URL if missing ---
if not moodle_base_url:
    print("[*] Moodle Base URL not found in config file.")
    while not moodle_base_url:
        moodle_base_url = input("Enter Moodle Base URL (e.g., https://your.moodle.com): ").strip()
        if not moodle_base_url.startswith(('http://', 'https://')):
             print("[!] Error: URL must start with http:// or https://")
             moodle_base_url = None

# Ensure trailing slash is removed for consistent URL building later
moodle_base_url = moodle_base_url.rstrip('/')

# --- Argument Parsing ---
parser = argparse.ArgumentParser(description="Download Moodle quiz results and overall grades for specific courses.")
parser.add_argument(
    'course_ids',
    metavar='COURSE_ID', type=str, nargs='+',
    help="One or more numeric IDs of the Moodle courses (Required)."
)
args = parser.parse_args()

print(f"[*] Target Course IDs: {', '.join(args.course_ids)}")
print(f"[*] Using Moodle Base URL: {moodle_base_url}")

# --- Credentials Priority: Config File > Prompt ---
moodle_username = None
moodle_password = None

# 1. Try config file first
if config_username and config_password:
    print(f"[*] Using credentials from {config_file}.")
    moodle_username = config_username
    moodle_password = config_password
elif config_username or config_password:
    print(f"[!] Warning: Incomplete username/password found in {config_file}. Prompting required.")
else:
    print(f"[*] No complete credentials found in {config_file}.")

# 2. If still no complete credentials, prompt user
if not moodle_username or not moodle_password:
    print("[*] Prompting for credentials.")
    moodle_username = input("Enter Moodle Username: ")
    moodle_password = getpass.getpass("Enter Moodle Password: ")

# --- SSL Verification Warning ---
if not verify_ssl:
    print("[!] Warning: SSL certificate verification is DISABLED. Use with caution.")
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
else:
    print("[*] SSL certificate verification is ENABLED.")

# --- Function to Process a Single Course ---
def process_course(session, course_id, base_results_dir, request_delay):
    """Logs steps and downloads results for a single Moodle course."""
    print(f"\n{'='*15} Processing Course ID: {course_id} {'='*15}")
    sesskey = None
    sanitized_course_name_for_dir = None
    course_name_for_file = None
    quiz_results_dir = None

    course_view_url = moodle_base_url + course_view_path + f"?id={course_id}"
    grade_export_setup_url = moodle_base_url + grade_export_setup_path + f"?id={course_id}"
    export_post_url = moodle_base_url + grade_export_post_path
    quiz_base_download_url = moodle_base_url + quiz_download_path

    try:
        if request_delay > 0: time.sleep(request_delay)

        # === Stage 2 (Per Course): Extract Sesskey and Course Name ===
        print(f"[*] Navigating to course page: {course_view_url}")
        response_course_page = session.get(course_view_url, verify=verify_ssl); response_course_page.raise_for_status()
        soup_course_page = BeautifulSoup(response_course_page.text, 'html.parser')

        course_h1 = soup_course_page.find('div', class_='page-header-headings').find('h1') if soup_course_page.find('div', class_='page-header-headings') else soup_course_page.find('h1')
        raw_course_name = None
        if course_h1: raw_course_name = course_h1.get_text(strip=True)
        else:
            title_tag = soup_course_page.find('title')
            if title_tag and ':' in title_tag.get_text(strip=True): raw_course_name = title_tag.get_text(strip=True).split(':', 1)[1].strip()

        sanitized_course_name_for_dir = sanitize_filename(raw_course_name) if raw_course_name else f"Course_ID_{course_id}"
        course_name_for_file = raw_course_name if raw_course_name else f"Course ID {course_id}"
        print(f"[*] Course Name: '{raw_course_name if raw_course_name else 'Not Found'}' (Dir: '{sanitized_course_name_for_dir}', File Prefix: '{course_name_for_file}')")
        quiz_results_dir = os.path.join(base_results_dir, sanitized_course_name_for_dir)

        sesskey_input = soup_course_page.find('input', {'name': 'sesskey'})
        if sesskey_input: sesskey = sesskey_input['value']; print(f"[*] Found Sesskey in form input: {sesskey}")
        else:
            logout_link = soup_course_page.find('a', href=lambda h: h and 'logout.php' in h and 'sesskey=' in h)
            if logout_link:
                try: sesskey = logout_link['href'].split('sesskey=')[1].split('&')[0]; print(f"[*] Found Sesskey in logout link: {sesskey}")
                except IndexError: pass
        if not sesskey:
            print("[!] Sesskey not found in form/link, searching JavaScript...")
            for script in soup_course_page.find_all('script'):
                if script.string:
                     match = re.search(r'["\']sesskey["\']\s*:\s*["\']([^"\']+)["\']', script.string)
                     if match: sesskey = match.group(1); print(f"[*] Found Sesskey in JavaScript: {sesskey}"); break
        if not sesskey:
            print(f"[!] Sesskey still not found, trying grade export page: {grade_export_setup_url}")
            if request_delay > 0: time.sleep(request_delay)
            resp_setup_sesskey = session.get(grade_export_setup_url, verify=verify_ssl); resp_setup_sesskey.raise_for_status()
            soup_setup_sesskey = BeautifulSoup(resp_setup_sesskey.text, 'html.parser')
            sesskey_input_setup = soup_setup_sesskey.find('input', {'name': 'sesskey'})
            if sesskey_input_setup: sesskey = sesskey_input_setup['value']; print(f"[*] Found Sesskey on grade export page: {sesskey}")

        if not sesskey: raise ValueError("Failed to find sesskey for this course.")

        os.makedirs(quiz_results_dir, exist_ok=True)
        print(f"[*] Ensured results directory exists: '{os.path.abspath(quiz_results_dir)}'")

        # === Stage 3 (Per Course): Find Quizzes and Download ===
        print(f"\n--- Processing Individual Quizzes for Course {course_id} ---")

        quiz_links = soup_course_page.find_all('a', href=re.compile(r'/mod/quiz/view\.php\?id=\d+'))
        if not quiz_links: print("[!] No quiz links found on the course page.")
        else:
            print(f"[*] Found {len(quiz_links)} potential quiz link(s).")
            quiz_data = {}
            for link in quiz_links:
                href = link.get('href', ''); match = re.search(r'id=(\d+)', href)
                if not match: continue
                quiz_id = match.group(1)
                raw_name = link.find('span', class_='instancename').get_text(strip=True).replace('Quiz', '').strip() if link.find('span', class_='instancename') else None
                quiz_name = raw_name if raw_name else f"Quiz ID {quiz_id}"
                if quiz_id not in quiz_data: quiz_data[quiz_id] = quiz_name
            if not quiz_data: print("[!] No valid quiz IDs extracted.")
            else:
                print(f"[*] Identified {len(quiz_data)} unique quizzes:")
                for qid, qname in quiz_data.items(): print(f"  - ID: {qid}, Name: {qname}")
                dl_count = 0
                for quiz_id, quiz_name in quiz_data.items():
                    print(f"\n[*] Processing Quiz ID: {quiz_id} (Name: {quiz_name})")
                    params = {'sesskey': sesskey, 'download': 'excel', 'id': quiz_id, 'mode': 'overview', 'attempts': 'enrolled_with', 'onlygraded': '', 'onlyregraded': '', 'slotmarks': '1'}
                    dl_url = quiz_base_download_url + "?" + requests.compat.urlencode(params)
                    print(f"[*]   Downloading from: {dl_url}")
                    try:
                        if request_delay > 0: time.sleep(request_delay)
                        resp = session.get(dl_url, verify=verify_ssl, allow_redirects=True); resp.raise_for_status()
                        ctype = resp.headers.get('Content-Type', '').lower(); cdisp = resp.headers.get('Content-Disposition', '')
                        print(f"[*]   Response Status: {resp.status_code}, Content-Type: {ctype}")
                        save_filename = None
                        fname_match = re.search(r'filename="?([^"]+)"?', cdisp, re.IGNORECASE)
                        if fname_match:
                            original_filename = unquote(fname_match.group(1).strip())
                            save_filename = sanitize_filename(original_filename)
                            print(f"[*]   Using filename from header (decoded): '{original_filename}' -> '{save_filename}'")
                        else:
                            print(f"[!]   Content-Disposition header missing/filename not found. Generating filename.")
                            generated_name = f"{course_name_for_file} {quiz_name} ID {quiz_id}.xlsx"
                            save_filename = sanitize_filename(generated_name)
                        full_save_path = os.path.join(quiz_results_dir, save_filename)
                        if 'spreadsheetml' in ctype or 'excel' in ctype or '.xlsx' in save_filename.lower():
                            with open(full_save_path, 'wb') as f: f.write(resp.content); print(f"[+]   Saved: '{full_save_path}'")
                            dl_count += 1
                        else: print(f"[!!!]   Download Failed: Unexpected Content-Type/Disposition for Quiz ID {quiz_id}.")
                    except requests.exceptions.RequestException as e: print(f"[!!!]   HTTP Error downloading quiz {quiz_id}: {e}")
                    except Exception as e: print(f"[!!!]   Error processing/saving quiz {quiz_id}: {e}")
                print(f"\n[*] Finished individual quizzes for course {course_id}. Successfully saved {dl_count} of {len(quiz_data)} identified quizzes.")

        # === Stage 4 (Per Course): Perform Overall Grade Export ===
        print(f"\n--- Processing Overall Course Grades Export for Course {course_id} ---")

        try:
            print(f"[*] Navigating to grade export setup page: {grade_export_setup_url}")
            if 'soup_setup_sesskey' in locals() and soup_setup_sesskey:
                 soup_setup = soup_setup_sesskey; print("[*] Re-using setup page content fetched for sesskey check.")
            else:
                 if request_delay > 0: time.sleep(request_delay)
                 response_setup = session.get(grade_export_setup_url, verify=verify_ssl); response_setup.raise_for_status()
                 soup_setup = BeautifulSoup(response_setup.text, 'html.parser')
            itemids = set()
            id_inputs = soup_setup.find_all('input', {'name': re.compile(r'^itemids\[\d+\]$')})
            for inp in id_inputs:
                match = re.search(r'\[(\d+)\]', inp.get('name', ''))
                if match: itemids.add(match.group(1))
            if not itemids: print("[!] Warning: Could not find any grade item IDs. Overall export might be empty/incorrect.")
            else: print(f"[*] Found {len(itemids)} grade item IDs on setup page.")
            payload_dict = { 'mform_isexpanded_id_gradeitems': '1', 'checkbox_controller1': '1', 'mform_isexpanded_id_options': '1',
                'id': course_id, 'sesskey': sesskey, '_qf__grade_export_form': '1', 'export_feedback': '0', 'display[letter]': '0', 'decimals': '2', 'submitbutton': 'Download'}
            extra_params = []
            for item_id in itemids: extra_params.extend([(f'itemids[{item_id}]', '0'), (f'itemids[{item_id}]', '1')])
            extra_params.extend([('export_onlyactive', '0'), ('export_onlyactive', '1'), ('display[real]', '0'), ('display[real]', '1'),
                                ('display[percentage]', '0'), ('display[percentage]', '2')])
            final_payload_list = list(payload_dict.items()) + extra_params
            export_headers = { 'Content-Type': 'application/x-www-form-urlencoded', 'Origin': moodle_base_url, 'Referer': grade_export_setup_url,
                'Sec-Fetch-Dest': 'document', 'Sec-Fetch-Mode': 'navigate', 'Sec-Fetch-Site': 'same-origin', 'Sec-Fetch-User': '?1', 'Upgrade-Insecure-Requests': '1',
                'sec-ch-ua': '"Chromium";v="134", "Not:A-Brand";v="24", "Google Chrome";v="134"', 'sec-ch-ua-mobile': '?0', 'sec-ch-ua-platform': '"Windows"'}
            print(f"[*] Sending POST request for overall grades export...")
            if request_delay > 0: time.sleep(request_delay)
            response_overall_export = session.post(export_post_url, headers=export_headers, data=final_payload_list, verify=verify_ssl, allow_redirects=True)
            response_overall_export.raise_for_status()
            overall_ctype = response_overall_export.headers.get('Content-Type', '').lower(); overall_cdisp = response_overall_export.headers.get('Content-Disposition', '')
            print(f"[*] Overall Export Response Status: {response_overall_export.status_code}, Content-Type: {overall_ctype}")
            save_filename = None
            fname_match = re.search(r'filename="?([^"]+)"?', overall_cdisp, re.IGNORECASE)
            if fname_match:
                original_filename = unquote(fname_match.group(1).strip())
                save_filename = sanitize_filename(original_filename)
                print(f"[*]   Using filename from header (decoded): '{original_filename}' -> '{save_filename}'")
            else:
                print(f"[!]   Content-Disposition header missing or filename not found. Generating filename.")
                generated_name = f"Overall Grades {course_name_for_file} ID {course_id}.xlsx"
                save_filename = sanitize_filename(generated_name)
            os.makedirs(quiz_results_dir, exist_ok=True)
            full_save_path = os.path.join(quiz_results_dir, save_filename)
            if 'spreadsheetml' in overall_ctype or 'excel' in overall_ctype or '.xlsx' in save_filename.lower():
                with open(full_save_path, 'wb') as f: f.write(response_overall_export.content); print(f"[+] Successfully downloaded overall grades to '{full_save_path}'")
            else: print("[!!!] Overall Grade Download Failed: Unexpected Content-Type/Disposition.")
        except requests.exceptions.RequestException as e_overall: print(f"[!!!] HTTP Error during overall grade export process for course {course_id}: {e_overall}")
        except Exception as e_overall_proc: print(f"[!!!] Error during overall grade export processing for course {course_id}: {e_overall_proc}"); import traceback; traceback.print_exc()

        print(f"\n{'='*15} Finished Course ID: {course_id} {'='*15}")

    # --- Error handling for this specific course ---
    except requests.exceptions.RequestException as e: print(f"[!!!] HTTP Error processing course {course_id}: {e}")
    except ValueError as e: print(f"[!!!] Configuration Error processing course {course_id}: {e}")
    except Exception as e: print(f"[!!!] Unexpected Error processing course {course_id}: {e}"); import traceback; traceback.print_exc()

# --- Main Execution ---
session = requests.Session()
session.headers.update({
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
    'Accept-Language': 'en-US,en;q=0.9', 'DNT': '1',
})

try:
    # --- Stage 1: Login Once ---
    login_url = moodle_base_url + login_path
    print(f"[*] Attempting to access login page: {login_url}")
    if request_delay > 0: time.sleep(request_delay)
    response_get = session.get(login_url, verify=verify_ssl); response_get.raise_for_status()
    soup_login = BeautifulSoup(response_get.text, 'html.parser')
    logintoken = soup_login.find('input', {'name': 'logintoken'})['value'] if soup_login.find('input', {'name': 'logintoken'}) else None
    if logintoken: print(f"[*] Found logintoken: {logintoken}")
    login_payload = {'username': moodle_username, 'password': moodle_password}
    if logintoken: login_payload['logintoken'] = logintoken
    print(f"[*] Submitting login credentials for user: {moodle_username}")
    if request_delay > 0: time.sleep(request_delay)
    response_post = session.post(login_url, data=login_payload, verify=verify_ssl); response_post.raise_for_status()
    if login_url in response_post.url:
        error_div = BeautifulSoup(response_post.text, 'html.parser').find('div', {'id': 'loginerrormessage'}) or \
                    BeautifulSoup(response_post.text, 'html.parser').find('div', class_='loginerrors')
        print(f"[!!!] Login Failed! Error: {error_div.get_text(strip=True) if error_div else 'Unknown'}."); sys.exit(1)
    print(f"[*] Login successful! Session established.")

    # --- Loop Through Courses ---
    for course_id_to_process in args.course_ids:
        process_course(session, course_id_to_process, base_results_dir, request_delay)

# --- Global Error Handling ---
except requests.exceptions.SSLError as e: print(f"[!!!] SSL Error occurred during initial connection: {e}\n     SSL verification is currently {'DISABLED' if not verify_ssl else 'ENABLED'}.")
except requests.exceptions.RequestException as e: print(f"[!!!] An initial HTTP error occurred (e.g., during login): {e}")
except ImportError as e: module_name = str(e).split("'")[-2]; print(f"[!!!] Import Error: {e}. Install missing module '{module_name}'.")
except Exception as e: print(f"[!!!] An unexpected critical error occurred: {e}"); import traceback; traceback.print_exc()
finally:
    if 'session' in locals() and session: session.close()
    print("\n[*] Script finished.")

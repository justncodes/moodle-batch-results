# Moodle Batch Results Downloader

## Purpose

This Python script automates the process of downloading grade reports from Moodle courses. It retrieves both:

1.  **Individual Quiz Results:** Downloads the detailed results report (as an `.xlsx` file) for each quiz found within the specified course(s).
2.  **Overall Course Grades:** Downloads the main course grade export (as an `.xlsx` file) containing all grade items for the specified course(s).

This is useful for instructors or administrators who need to regularly archive or analyze grade data from multiple Moodle courses or courses containing many quizzes without manually clicking through the Moodle interface for each one.

## How it Works

The script uses the `requests` and `BeautifulSoup` libraries to simulate a web browser and interact with Moodle:

1.  **Configuration:** Reads settings (Moodle URL, credentials, specific Moodle page paths, request delay, SSL settings) from a `config.ini` file located in the same directory. Prompts for missing essential configuration (URL, credentials) if not found in the file.
2.  **Login:** Logs into the specified Moodle instance using the obtained credentials, establishing an authenticated session.
3.  **Course Iteration:** Loops through each **Course ID** provided as a command-line argument.
4.  **Per-Course Processing:** For each Course ID:
    *   Navigates to the main course page (`/course/view.php`).
    *   Extracts the course name to use for creating an output directory and for fallback filenames.
    *   Extracts the Moodle `sesskey` required for authenticated actions.
    *   Creates a subdirectory named after the course.
    *   **Quiz Downloads:**
        *   Parses the course page to find links to all quiz activities (`/mod/quiz/view.php`).
        *   For each unique quiz found, constructs the URL for the Excel results download (`/mod/quiz/report.php?...download=excel`).
        *   Sends an HTTP GET request to download the quiz results file.
        *   Attempts to use the filename provided by the server's `Content-Disposition` header; otherwise, generates a descriptive filename.
        *   Saves the `.xlsx` file to the course-specific subdirectory.
    *   **Overall Grade Download:**
        *   Navigates to the grade export *setup* page (`/grade/export/xls/index.php`).
        *   Parses the setup page to dynamically find all available grade item IDs (`itemids`).
        *   Constructs the payload for the export POST request, including the dynamic `itemids`.
        *   Sends an HTTP POST request to the grade export *action* page (`/grade/export/xls/export.php`).
        *   Attempts to use the filename provided by the server's `Content-Disposition` header; otherwise, generates a descriptive filename.
        *   Saves the overall grades `.xlsx` file to the course-specific subdirectory.
    *   **Delay:** Optionally pauses between HTTP requests if configured in `config.ini`.

## Prerequisites

*   **Python 3:** The script is written for Python 3.
*   **Required Libraries:** You need to install `requests` and `beautifulsoup4`.
    ```bash
    pip install requests beautifulsoup4
    ```
*   **Moodle Access:** You need valid Moodle user credentials with sufficient permissions to:
    *   View the specified courses.
    *   View quizzes within those courses.
    *   View quiz attempt reports (`mod/quiz:viewreport`).
    *   Export course grades (`moodle/grade:export`).
    *   (Typically, a Teacher, Manager, or Administrator role is required).

## Setup

1.  **Save the Script:** Save the Python code as `get_course_results.py` (or your preferred name).

2.  **Create Configuration File (`config.ini`):**
    *   In the same directory as the script, create a file named `config.ini`.
    *   Add the following content. **You MUST provide `base_url`, `username`, and `password` either here or when prompted.** Sections `[Paths]` and `[Settings]` and their keys are optional; the script uses internal defaults if they are missing.

        ```ini
        [Moodle]
        base_url = https://your.moodle.url.here.com
        username = your_moodle_username_here
        password = your_moodle_password_here

        # OPTIONAL CONFIGURATIONS BELOW
        [Paths]
        # Relative paths for Moodle endpoints. Defaults should usually work.
        login_path = /login/index.php
        course_view_path = /course/view.php
        grade_export_setup_path = /grade/export/xls/index.php
        grade_export_post_path = /grade/export/xls/export.php
        quiz_download_path = /mod/quiz/report.php
        # Base directory for saving results (relative to script location or absolute)
        results_base_dir = .

        [Settings]
        # Delay between requests in seconds in case of rate limits. No delay by default.
        request_delay_seconds = 0.0
        # SSL Verification (true/false). Set to false if using a cert that would fail to validate (such as sef-signed).
        verify_ssl = false
        ```
    *   **Security:** Protect this file appropriately, as it may contain sensitive credentials. Restrict file permissions (e.g., `chmod 600 config.ini` on Linux/macOS).

3.  **Identify Course IDs:** You need the numeric **Course ID** for each course you want to process. You can usually find this in the URL when viewing the course page (e.g., `.../course/view.php?id=133` means the ID is `133`).

## Usage

Run the script from your terminal or command prompt, providing one or more Course IDs as arguments.

**Basic usage (using `config.ini` for URL and credentials, processing courses 133 and 134):**

```bash
python get_course_results.py 133 134
```

The script will create a sub-directory for each specified course (named after the course title, like `My Course Name` or `Course_ID_133` if the name can't be found) within the `results_base_dir`. Inside each course directory, it will save the downloaded `.xlsx` files for individual quizzes and the overall grades.

## Security Considerations

*   **Credentials:** Storing passwords in plain text `config.ini` files has security risks. Ensure the file has strict permissions (readable only by the intended user).
*   **SSL Verification (`verify_ssl`):** The default setting (`verify_ssl = false`) disables SSL certificate verification. This is often needed for internal Moodle instances using self-signed certificates. **Do not** set this to `false` if connecting to a Moodle site with a valid, trusted SSL certificate over the public internet, as it bypasses an important security check. Set `verify_ssl = true` in that case.

## Troubleshooting

*   **Config File Not Found / Read Error:** The script will warn you and prompt for the `base_url` and credentials. Ensure `config.ini` is correctly named and formatted if you intended to use it.
*   **Missing Base URL / Login Failed:** Double-check the `base_url` (either prompted or in config). Verify username/password (prompted or in config). Ensure `login_path` in `config.ini` (if modified) is correct. Check if the user account is locked or requires MFA (which this script doesn't support).
*   **HTTP Error processing course X / 404 Not Found:**
    *   Verify the Course ID `X` is correct and exists.
    *   Ensure the Moodle user has permission to view Course `X`.
    *   Check the `course_view_path` in `config.ini`.
*   **Failed to find sesskey:** This usually indicates an unexpected page structure after login or on the course page, or potentially a session issue. Check if the user is correctly logged in or if the Moodle theme drastically changes element locations.
*   **No quiz links found:** The script might not find quizzes if they are hidden, unavailable to the user, or if the HTML structure containing the links differs significantly from standard Moodle themes.
*   **Error downloading quiz/grades:**
    *   Check Moodle permissions (`mod/quiz:viewreport`, `moodle/grade:export`).
    *   The URL paths in `config.ini` (`quiz_download_path`, `grade_export_setup_path`, `grade_export_post_path`) might be incorrect for your Moodle version/setup.
    *   Dynamic item ID extraction for overall grades might fail if the form structure on the setup page has changed significantly.
*   **Download Failed: Unexpected Content-Type:** The server didn't return the expected Excel file type. This could indicate an error page was served instead of the file. Check Moodle logs or try the download manually.
*   **Filename Issues:** If filenames look strange (e.g., containing `%20`), there might be an issue with the `Content-Disposition` header from Moodle or the decoding/sanitization logic.
*   **Session Expired:** If processing many courses over a long time, the Moodle session might expire. Run the script for smaller batches of course IDs if needed.
*   **Connection Errors / SSL Errors:** Check network connectivity. If using `verify_ssl = true`, ensure your system trusts the Moodle server's certificate. If `verify_ssl = false`, ensure the warning message appears.

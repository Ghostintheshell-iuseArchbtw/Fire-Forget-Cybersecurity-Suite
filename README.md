# Fire-Forget-Cybersecurity-Suite
Fire&Forget Cybersecurity Suite is a PyQt5-based graphical user interface that automates the execution of penetration testing tools, including Gobuster, Rustscan, Nikto, and SQLMap. This suite is designed to streamline the process of web application testing and vulnerability assessment.
Features

    Gobuster: Directory and file brute-force tool.
    Rustscan: Fast and customizable port scanner.
    Nikto: Web server scanner with comprehensive tests.
    SQLMap: Automatic SQL injection and database takeover tool.

    Usage

    Clone the repository:

    bash

git clone https://github.com/your-username/FireAndForget.git
cd FireAndForget

Install dependencies:

bash

pip install PyQt5

Run the application:

bash

    python fire_and_forget.py

    Input the target URL, click "FIRE&FORGET," and let the suite automate the penetration testing tools.

    To exit the suite, click "FLEE_THE_FIGHT" or close the application window.

Requirements

    Python 3.x
    PyQt5
    Gobuster
    Rustscan
    Nikto
    SQLMap
    Metasploit Framework (optional, for msfconsole)

License

This project is licensed under the MIT License - see the LICENSE.md file for details.
Contributing

Feel free to contribute by opening issues, suggesting features, or submitting pull requests. Your contributions are highly appreciated!
GitHub Commits
Initial Commit

    Created the Fire&Forget Cybersecurity Suite application.
    Implemented the GUI using PyQt5 for user interaction.
    Integrated Gobuster, Rustscan, Nikto, and SQLMap into the suite.

Feature: SQLMap Integration

    Modified the script to incorporate SQLMap into the suite.
    Updated the run_scan method to launch SQLMap for potential web servers found by Rustscan.

Code Refactoring

    Improved code readability and maintainability.
    Organized the code into a structured layout using classes and methods.

UI Enhancement

    Updated the UI layout for better aesthetics.
    Added a "FLEE_THE_FIGHT" button for a quick exit option.

Documentation Update

    Updated the README.md file with detailed information about the suite.
    Provided instructions for installation and usage.

Bug Fix

    Resolved a bug related to screen resolution calculation.
    Ensured the application works across different screen sizes.

Security Considerations

    Added warnings and considerations regarding the use of sudo for Gobuster.
    Emphasized the responsible and ethical use of cybersecurity tools.
Todo
    Improve UI,better error handling and logging,more tools and distro cross compatibility implmentation

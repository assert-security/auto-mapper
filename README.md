# Auto Mapper - powered by Venari

Auto Mapper Integrates Burp with Venari to deliver fully automatic login and site mapping to Burp users.  AppSec testing is raised to a new level of efficiency by starting with a detailed map of site URLs.  The login is completely automatic in most cases and Session state is maintained throughout the scan.  Start with a point and shoot scan and then apply all of Burp's advanced techniques on the discovered content.


In parallel with discovery, the Auto Mapper extension finds DOM XSS, CSRF and broken authentication vulnerabilities.


The full power of Burp can be applied to a detailed site-map loaded by the Auto Mapper extension.

This extension requires Venari Community Edition (or higher) <a href='https://assertsecurity.io/community-edition/' target='_blank' >Download Venari</a>

## Features

- Automatic login using only credential information

- Automatic site mapping via browser discovery and link spidering

- Easy customization of discovery scope in the free Venari Community Edition UI

- Easy customization of exploit rules in the free Venari Community Edition UI

- Manually record workflows as needed for advanced use cases. Examples:

    - Create login workflows for cases where auto-login does not work

    - Create account with user registration workflow

- Automatic XSS probing and fuzzing (reflected, DOM-based, stored)

- CSRF testing

- Broken session management testing

    - Session ID unchanged after login
    - Incomplete logout functionality
    - Credentials stored in cookie

- Import Venari data
    - Site map from a completed job
    - All data from a completed job (site map and issues)
    - Issues for an application (aggregated from all scan jobs)


## Building the extension from GitHub source code

- Get the code from <a href= 'https://github.com/assert-security/auto-mapper' target='_blank' >Auto Mapper GitHub repository</a>

- Install JDK version 8 or greater

- Install Gradle

- Run the command below:

```
gradle fatJar
```

- The jar file will be written to the build/libs folder

## Usage

- The Auto Mapper extension requires Venari Community edition to be running on the same computer as Burp. Venari CE is cross-platform and can be downloaded for free. <a href='https://assertsecurity.io/community-edition/' target='_blank' >Download Venari Community Edition</a> install it and run  it.

- Create a named application for a web site under test and provide login credentials (if applicable) using the Venari UI.

- In the right click context menu in Burp, click 'Start Venari Scan' and select the application name created above.

- Watch the target tab to see the sitemap details populated in real time.  Issues will show up as they are found.


## Tutorials

<a href='https://assertsecurity.io/venaridocs/quick-starts/community-edition/quick-start/' target='_blank' >Venari CE Quick Start Guide</a>

<a href='https://youtu.be/bEeABJm9WYQ' target='_blank' >Auto Mapper Quick Start Video</a>

<a href='https://assertsecurity.io/venaridocs/quick-starts/tips-and-tricks/burp-auto-mapper/auto-mapper/' target='_blank' >Auto Mapper Quick Start Article</a>

## Support and Feature Requests

<a href='https://assertsecurity.io/support/' target='_blank' >Support and Feature Requests</a>

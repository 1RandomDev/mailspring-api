# Selfhosted reimplementation of the Mailspring API

Free reimplementation of the Mailspring Sync backend (and other required APIs). This project aims to provide an alternative sync server that can be self hosted for the [Mailspring Email Client](https://getmailspring.com/).

**Note:** This project is in an early state of development and will probably still contain a lot of bugs.

## Supported Features
- :heavy_check_mark: Metadata Sync
- :x: Multiple user accounts (work in progress)
- :heavy_check_mark: Read Receipts
- :heavy_check_mark: Link Tracking
- :heavy_check_mark: Follow-up Reminders
- :heavy_check_mark: Snooze messages
- :heavy_check_mark: Send Later
- :heavy_check_mark: Mail Templates
- :x: Rich contact profile
- :x: Company overviews
- :heavy_check_mark: Mailbox insights + sharing
- :x: Translation
- :x: Thread sharing

## Environment variables
| Variable | Description | Default |
|----------|-------------|---------|
| LOG_LEVEL | Set custom log level. [Available log levels](https://github.com/winstonjs/winston#logging-levels). | `info` |
| SHARE_URL | External url for shared resources. (Should be on a different domain for securrity purposes.) | `http://localhost:5101` |
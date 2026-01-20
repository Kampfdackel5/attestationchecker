# Attestation Checker

This was the code used for my bachelors thesis at FU Berlin. It was meant to be accessible to my supervisors, but got forked, so I thought I would give a brief overview.

The code is to be used with Android Studio, with which it can be packaged into an apk. It relies on a webserver which can receive and interpret the requests from the app. To use the app, you have to specify the server in the code and setup the webserver to decode the certificate (DER Base64 with ASN.1 structure).

If someone is interested in the server-side code or my bachelors thesis explaining the process, please send me a text on signal (Matthias5.43) and I will see if I can still find everything.

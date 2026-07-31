# Self passport registration mobile target

This package selects the `passport-register` feature of the shared native
Rapidsnark Mobench adapter. It exists as a separate package because Mobench
0.1.48 does not expose Cargo feature selection; a separate package keeps the
499.11 MB registration zkey out of the smaller disclosure app.

# Native Self Passport registration adapter

This package is the registration half of the historical Self Passport
counterpart. It is paired with the disclosure adapter for the named
`passport_complete_age_check` product-flow rows; it is not a monolithic Noir
age-check proof. The exact zkey, witness, and source commit are retained in
the row provenance and lock files.

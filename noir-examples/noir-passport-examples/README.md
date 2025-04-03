# Noir passport example programs
Note: Everything in `zkpassport_libs` was copy/pasted from https://github.com/zkpassport/circuits/tree/main/src/noir/lib. Unfortunately Noir does not yet have a methodology for importing from a GitHub repository which contains more than one workspace member.

## To compile (age check only for now)
* Navigate to the `complete_age_check` directory: `cd complete_age_check`
* Run `./scripts/compile.sh complete_age_check`
* The result should be in `complete_age_check/target/complete_age_check.json`
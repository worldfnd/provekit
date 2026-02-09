# Get the name of the package from the argument
package_name=$1

# Compile the circuit and get the number of the gates
# nargo compile --force --package $package_name && bb gates -b ./target/$package_name.json --recursive > ./info/$package_name.json
# nargo compile --force --package $package_name
nargo compile --skip-underconstrained-check --skip-brillig-constraints-check --force --print-acir --package $package_name 
# bb gates -b ./target/$package_name.json --recursive
#!/bin/bash

# Run Golang tests for each test code and save the output to variables
elgamla_test_output=$(go test ./crypto/elgamal/...)
millionaire_test_output=$(go test ./crypto/millionaire/...)
mta_test_output=$(go test ./crypto/mta/...)
ecdsa_test_output=$(go test ./crypto/ecdsa/...)
lindell17_test_output=$(go test ./crypto/lindell17/...)
twoecdsa_test_output=$(go test ./crypto/twoecdsa/...)


# Parse the output of each test code to determine the pass count and success/failure status
elgamal_pass_count=$(echo "$elgamla_test_output" | grep -c 'ok')
millionaire_pass_count=$(echo "$millionaire_test_output" | grep -c 'ok')
mta_pass_count=$(echo "$mta_test_output" | grep -c 'ok')
ecdsa_pass_count=$(echo "$ecdsa_test_output" | grep -c 'ok')
lindell17_pass_count=$(echo "$lindell17_test_output" | grep -c 'ok')
twoecdsa_pass_count=$(echo "$twoecdsa_test_output" | grep -c 'ok')

# Calculate the total pass count
pass_count=$((elgamal_pass_count + millionaire_pass_count + mta_pass_count + ecdsa_pass_count + lindell17_pass_count + twoecdsa_pass_count))

# Output the summary for each test code
echo "elgamal tests:"
echo "Passed: $elgamal_pass_count"
echo "millionaire tests:"
echo "Passed: $millionaire_pass_count"
echo "mta tests:"
echo "Passed: $mta_pass_count"
echo "ecdsa tests:"
echo "Passed: $ecdsa_pass_count"
echo "lindell17 tests:"
echo "Passed: $lindell17_pass_count"
echo "twoecdsa tests:"
echo "Passed: $twoecdsa_pass_count"

# Output the total pass count
echo "Total Passed: $pass_count"

# Check if all tests passed
if [ $pass_count -eq 6 ]; then
  echo "All tests passed!"
else
  # raise an error if any test failed
  echo "Some tests failed!"
  exit 1
fi

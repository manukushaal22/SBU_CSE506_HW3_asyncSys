echo "randomtext" >> tmpin
echo "Before Encryption"
cat tmpin
./jobmanager -i -e tmpin tmpencout passwordpassword -l -p
echo "After Encryption"
cat tmpencout
./jobmanager -i -d tmpencout tmpdecout passwordpassword -l -p
echo "After Decryption"
cat tmpdecout
rm tmpin tmpencout tmpdecout

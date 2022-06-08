echo "randomtext" >> tmpin
echo "Before Compression"
cat tmpin
ls tmpin
./jobmanager -i -p tmpin tmpencout -l -p
echo "After Compression"
cat tmpencout
ls tmpencout
./jobmanager -i -u tmpencout tmpdecout -l -p
echo "After Decompression"
cat tmpdecout
ls tmpdecout
rm tmpin tmpencout tmpdecout

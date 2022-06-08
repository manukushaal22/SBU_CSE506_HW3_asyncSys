echo "randomtext" >> tmpin
cat tmpin
echo "Polling"
./jobmanager -i -s tmpin -l -p
echo "Fileout"
./jobmanager -i -s tmpin -l -f
ls /async_job_outs/
rm tmpin

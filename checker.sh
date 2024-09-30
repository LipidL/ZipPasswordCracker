max_password=99999
for i in $(seq -f "%05g" 0 $max_password); do
    echo "checking password: $i"
    ./zip text.zip $i
    ./encrypt text.zip 5
done
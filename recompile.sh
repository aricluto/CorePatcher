for i in {1..5}; do
    if [ -d "classes${i:+$i}" ]; then
        echo "Recompiling classes${i:+$i} to classes${i:+$i}.dex"
        java -jar smali/smali/build/libs/smali.jar a -a 34 "classes${i:+$i}" -o "framework/classes${i:+$i}.dex"
    else
        break
    fi
done
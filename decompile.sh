for i in {1..10}; do
    if [ -f "framework/classes${i:+$i}.dex" ]; then
        echo "Decompiling classes${i:+$i}.dex"
        java -jar smali/baksmali/build/libs/baksmali.jar d -a 34 "framework/classes${i:+$i}.dex" -o "classes${i:+$i}"
    else
        break
    fi
done
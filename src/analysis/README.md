## Build
```
./patch-loader.sh <path/to/loader> [your new loader path]

./patch-libc.sh <path/to/libc.so.6> [new libc path]
```

## Usage
```
./your_loader.so  <your program> <your parameters>
```
OR
```
LD_PRELOAD=/path/to/new_libc.so.6 ./your_loader.so <your program> <your parameters>
```

## Instructions



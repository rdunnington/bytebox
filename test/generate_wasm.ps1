$wasts = Get-ChildItem "specmirror" -Filter *.wast

if ((Test-Path 'wasm') -eq $false) {
    mkdir 'wasm'
}

pushd wasm

foreach ($file in $wasts)
{
    $output_dir = [System.IO.Path]::GetFileNameWithoutExtension($file.FullName)

    if ((Test-Path $output_dir) -eq $false) {
        mkdir $output_dir
    }

    pushd $output_dir
    ..\..\wast2json.exe $file.FullName
    popd
}

popd

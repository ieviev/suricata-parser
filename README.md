# Suricata rules downloader/parser

## Dependencies:

- python 3
- dotnet-sdk 5.0+

## Usage

```
dotnet fsi ./main.fsx
```

## Troubleshooting

##### `error NU1101: Unable to find package FSharp.Data`
```
dotnet nuget add source --Name "NuGet official package source" --Source "https://api.nuget.org/v3/index.json"
```


## License

[MIT](https://choosealicense.com/licenses/mit/)
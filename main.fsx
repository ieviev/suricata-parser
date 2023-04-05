[<Literal>]
let SuricataVersion = "6.7.0"

#r "System.Formats.Tar"

open System
open System.IO
open System.Text
open System.IO.Compression

Directory.SetCurrentDirectory(__SOURCE_DIRECTORY__)

let hc = new System.Net.Http.HttpClient()

// #1. get current suricata rules version
// https://rules.emergingthreats.net/open/suricata-6.7.0/
let rulesVersion =
    hc
        .GetStringAsync($"https://rules.emergingthreats.net/open/suricata-{SuricataVersion}/version.txt")
        .Result.TrimEnd()

printfn $"suricata rules version: {rulesVersion}"

let rulesDir = $"rules/suricata-{rulesVersion}"
Directory.CreateDirectory(rulesDir) |> ignore

// #2. download suricata rules
let downloadRules () =
    task {
        printfn "downloading rules.."

        let! tarGzStream =
            hc.GetStreamAsync(
                $"https://rules.emergingthreats.net/open/suricata-{SuricataVersion}/emerging-all.rules.tar.gz"
            )

        use decompressedStream = new GZipStream(tarGzStream, CompressionMode.Decompress)
        printfn $"extracting rules to {rulesDir}.."
        do! Formats.Tar.TarFile.ExtractToDirectoryAsync(decompressedStream, rulesDir, overwriteFiles = true)
    }

downloadRules().Result

// #3. parse suricata rules
let rulesPath = rulesDir + "/emerging-all.rules"

let run (ps: string, args: string) =
    System.Diagnostics.Process.Start(ps, args)

printfn "parsing rules to suricata.json.."

let parseRulesToJson () =
    run("virtualenv", "-q env").WaitForExit()
    run("env/bin/python3", $"dump-rules.py \"{rulesPath}\"").WaitForExit()

parseRulesToJson ()

// #4. convert and filter rules in dotnet
printfn "processing and filtering rules.."
#r "nuget: FSharp.Data"
open FSharp.Data

[<Literal>]
let Sample = __SOURCE_DIRECTORY__ + "/samples/suricatasmall.json"

type Suricata = FSharp.Data.JsonProvider<Sample, InferenceMode=Runtime.StructuralInference.InferenceMode.NoInference>
let suricata = "suricata.json" |> File.ReadAllText |> Suricata.Parse

let suricataRules =
    suricata
    |> Array.collect (fun rule ->
        rule.Options
        |> Array.where (fun opt -> opt.Name = "pcre")
        |> Array.map (fun opt ->
            if opt.Value.Record.IsSome then
                failwith $"failed to parse {opt}"
            else
                {|
                    Category = rule.Classtype
                    Msg = rule.Msg
                    Pattern = opt.Value.String.Value
                |}))

let distinctRules = suricataRules |> Array.distinctBy (fun x -> x.Pattern)
printfn $"found %i{suricataRules.Length} rules (%i{distinctRules.Length} distinct)"

// #5. write pcre rules to table
let pcreFile = $"suricata-{rulesVersion}-pcre.tsv"
printfn $"exporting PCRE patterns to {Path.Combine(rulesDir, pcreFile)}.."
#r "nuget: CsvHelper, 30.0.1"
open CsvHelper

let exportToTsv (data: _, outputFile: string) =
    let config =
        Configuration.CsvConfiguration(
            Globalization.CultureInfo.InvariantCulture,
            Delimiter = "\t",
            ShouldQuote = (fun x -> false)
        )

    use sw = new StreamWriter(outputFile)
    use csvw = new CsvWriter(sw, config)
    csvw.WriteRecords(data)

exportToTsv (distinctRules, Path.Combine(rulesDir, pcreFile))

// #6. converting pcre patterns to .NET
let netFile = $"suricata-{rulesVersion}-net.tsv"
printfn $"exporting .NET patterns to {Path.Combine(rulesDir, netFile)}.."
module Pcre =
    open System.Text.RegularExpressions
    let regexReplace (oldv: string, newv: string) (input: string) = Regex.Replace(input, oldv, newv)

    /// /a/i -> a
    let escapeOuter (pat: string) =
        let opts = "[HiRmUsxu]"
        Regex.Replace(pat.TrimStart('/'), $"/({opts}){{0,3}}$", "")

    /// (?P<name>) -> (?<name>)
    let editNamedGroups (pat: string) =
        Regex.Replace(pat, @"\(\?P=(.*?)\)", @"\k<$1>").Replace("(?P<", "(?<")

    let editEscapePatterns (pat: string) =
        pat
            .Replace("\\/", "/") // slashes are not escaped in .net
            .Replace("\\_", "_") // underscores are not escaped in .net
            .Replace("\\<", "<") // not escaped in .net
            .Replace("\\:", ":") // underscores are not escaped in .net
            .Replace("\\g", "\\G") // ??
        // mastering reg exprs: perl page 286
        // The \x{num} syntax accepts any number of digits
        |> regexReplace (@"\\x([0-9a-fA-F])([^0-9a-fA-F])", @"\x0$1$2")
        |> regexReplace (@"\\x([^0-9a-fA-F])", @"\x00$1") // \x should be \x00

    let removePossessiveQuantifiers (pat: string) =
        Regex.Replace(pat, @"(\*|\}|\?|\+)\+", @"$1")

    let toDotnet (pat: string) =
        pat |> escapeOuter |> editNamedGroups |> editEscapePatterns |> removePossessiveQuantifiers

let distinctRulesDotnet = 
    distinctRules |> Array.map (fun x -> {| x with Pattern = Pcre.toDotnet (x.Pattern.Trim('\"')) |})

exportToTsv(distinctRulesDotnet,Path.Combine(rulesDir, netFile))

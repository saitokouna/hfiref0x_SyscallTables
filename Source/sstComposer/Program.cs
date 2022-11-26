/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2014 - 2022
*
*  TITLE:       PROGRAM.CS
*
*  VERSION:     1.30
*
*  DATE:        25 Nov 2022
*
*  SSTC entrypoint.
* 
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

using System;
using System.IO;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Reflection;

namespace sstc
{
    public class sstTable
    {
        public int[] Indexes;
        public string ServiceName;
    }

    public enum OptionTypeEnum
    {
        /// <summary>
        /// A Long Name for an Option, e.g. --opt.
        /// </summary>
        LongName,

        /// <summary>
        /// A Short Name for an Option, e.g. -o.
        /// </summary>
        ShortName,

        /// <summary>
        /// A Symbol, that is neither a switch, nor an argument.
        /// </summary>
        Symbol
    }

    /// <summary>
    /// An option passed by a Command Line application.
    /// </summary>
    public class CommandLineOption
    {
        /// <summary>
        /// The Name of the Option.
        /// </summary>
        public string Name { get; set; }

        /// <summary>
        /// The Value associated with this Option.
        /// </summary>
        public string Value { get; set; }

        /// <summary>
        /// The Type of this Option.
        /// </summary>
        public OptionTypeEnum OptionType { get; set; }
    }

    /// <summary>
    /// A simple parser to parse Command Line Arguments (https://www.bytefish.de/blog/command_line_parser.html)
    /// </summary>
    public static class CommandLineParser
    {
        public static IList<CommandLineOption> ParseOptions(string[] arguments)
        {
            // Holds the Results:
            var results = new List<CommandLineOption>();

            CommandLineOption lastOption = null;

            foreach (string argument in arguments)
            {
                // What should we do here? Go to the next one:
                if (string.IsNullOrWhiteSpace(argument))
                {
                    continue;
                }

                // We have found a Long-Name option:
                if (argument.StartsWith("--", StringComparison.Ordinal))
                {
                    // The previous argument was an option, too. Let's give it back:
                    if (lastOption != null)
                    {
                        results.Add(lastOption);
                    }

                    lastOption = new CommandLineOption
                    {
                        OptionType = OptionTypeEnum.LongName,
                        Name = argument.Substring(2)
                    };
                }
                // We have found a Short-Name option:
                else if (argument.StartsWith("-", StringComparison.Ordinal))
                {
                    // The previous argument was an option, too. Let's give it back:
                    if (lastOption != null)
                    {
                        results.Add(lastOption);
                    }

                    lastOption = new CommandLineOption
                    {
                        OptionType = OptionTypeEnum.ShortName,
                        Name = argument.Substring(1)
                    };
                }
                // We have found a symbol:
                else if (lastOption == null)
                {
                    results.Add(new CommandLineOption
                    {
                        OptionType = OptionTypeEnum.Symbol,
                        Name = argument
                    });
                }
                // And finally this is a value:
                else
                {
                    // Set the Value and return this option:
                    lastOption.Value = argument;

                    results.Add(lastOption);

                    // And reset it, because we do not expect multiple parameters:
                    lastOption = null;
                }
            }

            if (lastOption != null)
            {
                results.Add(lastOption);
            }

            return results;
        }
    }


    class Program
    {
        static int IndexOfItem(string ServiceName, List<sstTable> DataItems)
        {
            for (int i = 0; i < DataItems.Count; i++)
            {
                var Entry = DataItems[i];
                if (Entry.ServiceName == ServiceName)
                    return i;
            }
            return -1;
        }

        public class ItemsComparer : IComparer
        {
            public int Compare(Object x, Object y)
            {
                int a = Convert.ToInt32(Path.GetFileNameWithoutExtension(x as string));
                int b = Convert.ToInt32(Path.GetFileNameWithoutExtension(y as string));

                if (a == b)
                    return 0;

                if (a > b)
                    return 1;
                else
                    return -1;
            }
        }

        static void Main(string[] args)
        {
            bool outputAsHtml = false, outputWin32k = false;
            string tablesDirectory = "tables";       

            System.Console.WriteLine("SSTC - System Service Table Composer");
            var assembly = Assembly.GetEntryAssembly();
            var hashId = assembly.ManifestModule.ModuleVersionId;
            Console.WriteLine("Build MVID: " + hashId);

            //
            // Parse params.
            //

            var result = CommandLineParser.ParseOptions(args).ToArray();

            foreach (var param in result)
            {
                if (param.Name == "h")
                {
                    outputAsHtml = true;
                }
                else if (param.Name == "w")
                {
                    outputWin32k = true;
                }
                else if (param.Name == "d")
                {
                    if (param.Value != null)
                    {
                        tablesDirectory = param.Value;
                    }
                    else
                    {
                        Console.WriteLine("-d found but input tables directory is not specified, default will be used");
                    }
                } else
                {
                    Console.WriteLine("Unrecognized command \"{0}\"", param.Name);
                }
            }

            string tablesSubDirectory = (outputWin32k) ? "win32k" : "ntos";

            //
            // Combine path to the tables.
            //

            string LookupDirectory = Path.Combine(Directory.GetCurrentDirectory(), tablesDirectory);
            LookupDirectory = Path.Combine(LookupDirectory, tablesSubDirectory);

            string[] Tables;

            try
            {
                Tables = Directory.GetFiles(LookupDirectory, "*.txt");
            }
            catch (Exception e)
            {
                System.Console.WriteLine(e.Message);
                return;
            }

            IComparer Comparer = new ItemsComparer();
            Array.Sort(Tables, Comparer);

            int tablesCount = Tables.Count();

            List<sstTable> DataItems = new List<sstTable>();

            //
            // Makrdown header.
            //

            string MarkdownHeader = "| # | ServiceName |";
            string MarkdownSubHeader = "| --- | --- | ";

            //
            // Parse files into internal array.
            //

            int nIndex = 0;

            foreach (var sName in Tables)
            {
                string[] fData;
                MarkdownHeader += (Path.GetFileNameWithoutExtension(sName) + " | ");

                try
                {
                    fData = File.ReadAllLines(sName);
                    for (int i = 0; i < fData.Count(); i++)
                    {
                        int u = 0;
                        int syscall_id;
                        string syscall_name;

                        u = fData[i].IndexOf('\t') + 1;

                        syscall_id = Convert.ToInt32(fData[i].Substring(u));
                        syscall_name = fData[i].Substring(0, u - 1);

                        int id = IndexOfItem(syscall_name, DataItems);
                        if (id != -1)
                        {
                            var sstEntry = DataItems[id];
                            sstEntry.Indexes[nIndex] = syscall_id;
                        }
                        else
                        {
                            var sstEntry = new sstTable();
                            sstEntry.ServiceName = syscall_name;
                            sstEntry.Indexes = new int[tablesCount];
                            for (int k = 0; k < tablesCount; k++)
                                sstEntry.Indexes[k] = -1;
                            sstEntry.Indexes[nIndex] = syscall_id;
                            DataItems.Add(sstEntry);
                        }
                    }

                }
                catch (Exception e)
                {
                    System.Console.WriteLine(e.Message);
                }
                nIndex++;
                MarkdownSubHeader += (" --- | ");
            }

            FileStream outputFile;
            ASCIIEncoding asciiEncoding = new ASCIIEncoding();
            MemoryStream ms = new MemoryStream();
            var sw = new StreamWriter(ms, asciiEncoding);

            try
            {
                if (!outputAsHtml)
                {
                    Console.WriteLine("Composing markdown table");

                    //
                    // Generate markdown table as output.
                    //

                    string fileName = (outputWin32k) ? "w32ksyscalls.md" : "syscalls.md";

                    outputFile = new FileStream(fileName, FileMode.Create, FileAccess.Write);
                    sw.WriteLine(MarkdownHeader);
                    sw.WriteLine(MarkdownSubHeader);

                    int count = 0;

                    foreach (var Entry in DataItems)
                    {
                        count += 1;

                        var s = "| " + count.ToString("0000") + " | ";
                        s += Entry.ServiceName + " | ";

                        for (int i = 0; i < tablesCount; i++)
                        {
                            if (Entry.Indexes[i] != -1)
                            {
                                s += Entry.Indexes[i].ToString() + " | ";
                            }
                            else
                            {
                                s += "  | ";
                            }
                        }
                        sw.WriteLine(s);
                    }

                    sw.Flush();
                    ms.WriteTo(outputFile);
                    outputFile.Close();
                    ms.Dispose();
                    sw.Close();

                }
                else
                {
                    //
                    // Generate HTML table as output.
                    //
                    Console.WriteLine("Composing HTML table");

                    string ReportHead = "<!DOCTYPE html><html><head><style>body { font-family: \"Segoe UI\", -apple-system, BlinkMacSystemFont, Roboto, Oxygen-Sans, Ubuntu, Cantarell, " +
                        "\"Helvetica Neue\", sans-serif; line-height: 1.4; color: #333; background-color: #fff; padding: 0 5vw;} table { margin: 1em 0; border-collapse:" +
                        " collapse; border: 0.1em solid #d6d6d6;} caption { text-align: left; padding: 0.25em 0.5em 0.5em 0.5em;}th,td { padding: 0.25em 0.5em 0.25em 1em;" +
                        " vertical-align: text-top; text-align: left; text-indent: -0.5em; border: 0.1em solid #d6d6d6;}th { vertical-align: bottom; background-color: #666; color: #fff;}tr:nth-child(even) th[scope=row]" +
                        " { background-color: #f2f2f2;}tr:nth-child(odd) th[scope=row] { background-color: #fff;}tr:nth-child(even) { background-color: rgba(0, 0, 0, 0.05);}tr:nth-child(odd)" +
                        " { background-color: rgba(255, 255, 255, 0.05);}th { position: -webkit-sticky; position: sticky; top: 0; z-index: 2;}th[scope=row] " + 
                        "{ position: -webkit-sticky; position: sticky; left: 0; z-index: 1;}th[scope=row] { vertical-align: top; color: inherit; background-color: inherit; " + 
                        "background: linear-gradient(90deg, transparent 0%, transparent calc(100% - .05em), #d6d6d6 " +
                        "calc(100% - .05em), #d6d6d6 100%);}table:nth-of-type(2) th:not([scope=row]):first-child { left: 0; z-index: 3; background: linear-gradient(90deg, #666 0%, #666 " +
                        "calc(100% - .05em), #ccc calc(100% - .05em), #ccc 100%);}th[scope=row] + td { min-width: 24em;}th[scope=row]" +
                        " { min-width: 20em;}body { padding-bottom: 90vh;}</style></head><body>";

                    string ColStart = "<td>";
                    string ColEnd = "</td>";
                    string RowEnd = "</tr>";

                    string ReportEnd = "</table></body></html>";
                    string TableHead = "<table><caption>";

                    if (outputWin32k)
                        TableHead += "Win32k syscalls";
                    else
                        TableHead += "Ntos syscalls";

                    TableHead += "</caption><tr><th>#</th><th>ServiceName</th>";

                    for (int i = 0; i < tablesCount; i++)
                    {
                        TableHead += "<th>" +
                            Path.GetFileNameWithoutExtension(Tables[i]) + "</th>";

                    }
                    TableHead += RowEnd;

                    string fileName = (outputWin32k) ? "w32ksyscalls.html" : "syscalls.html";
                    outputFile = new FileStream(fileName, FileMode.Create, FileAccess.Write);

                    sw.WriteLine(ReportHead);
                    sw.WriteLine(TableHead);

                    for (int i = 0; i < DataItems.Count; i++)
                    {
                        var Entry = DataItems[i];
                        var item = "<tr><td>" + (i + 1).ToString() + ColEnd;
                        item += ColStart + Entry.ServiceName + ColEnd;

                        for (int j = 0; j < tablesCount; j++)
                        {
                            item += ColStart;
                            if (Entry.Indexes[j] != -1)
                            {
                                item += Entry.Indexes[j].ToString();
                            }
                            else
                            {
                                item += " ";
                            }
                            item += ColEnd;
                        }
                        item += RowEnd;
                        sw.WriteLine(item);
                    }

                    sw.WriteLine(ReportEnd);
                    sw.Flush();
                    ms.WriteTo(outputFile);
                    outputFile.Close();
                    ms.Dispose();
                    sw.Close();

                }

            } //try
            catch (Exception e)
            {
                System.Console.WriteLine(e.Message);
                System.Console.ReadKey();
            }
        }
    }
}

using System.Drawing.Imaging;
using SysmonAnalyzer.Analysis;
using SysmonAnalyzer.Forms;
using SysmonAnalyzer.Parsing;

namespace SysmonAnalyzer;

internal static class Program
{
    [STAThread]
    private static int Main(string[] args)
    {
        ApplicationConfiguration.Initialize();

        // 검증용: SysmonAnalyzer.exe --snapshot <출력폴더> <파일...>
        //  각 탭을 PNG로 저장하고 요약(report.txt, report.html)을 쓴 뒤 종료.
        if (args.Length >= 3 && args[0] == "--snapshot")
            return Snapshot(args[1], args.Skip(2).ToArray());

        var form = new MainForm();
        var files = args.Where(File.Exists).ToArray();
        if (files.Length > 0) form.Shown += async (_, _) => await form.LoadFilesAsync(files, false);
        Application.Run(form);
        return 0;
    }

    private static int Snapshot(string outDir, string[] args)
    {
        // --zoom=1.5 : 화면 배율 지정 (확대 기능 검증용)
        var zoomArg = args.FirstOrDefault(a => a.StartsWith("--zoom="));
        float zoom = zoomArg != null ? float.Parse(zoomArg[7..], System.Globalization.CultureInfo.InvariantCulture) : 1f;
        var files = args.Where(a => !a.StartsWith("--")).ToArray();
        Directory.CreateDirectory(outDir);
        var events = files.SelectMany(f => EventLoader.LoadFile(f, null, CancellationToken.None)).ToList();
        var result = AnalysisResult.Build(events, files.Select(Path.GetFileName)!);

        using (var w = new StreamWriter(Path.Combine(outDir, "report.txt")))
        {
            w.WriteLine($"events={result.Events.Count} processes={result.Processes.Count} roots={result.Roots.Count} " +
                        $"created={result.Processes.Values.Count(p => p.HasCreateEvent)} conns={result.Connections.Count} alerts={result.Alerts.Count}");
            w.WriteLine("localIps=" + string.Join(",", result.LocalIps));
            foreach (var a in result.Alerts)
                w.WriteLine($"[{a.Level}] {a.Rule} | {a.Process?.Label} | {a.Detail}");
        }
        File.WriteAllText(Path.Combine(outDir, "report.html"), ReportWriter.Build(result));

        var form = new MainForm { StartPosition = FormStartPosition.Manual, Location = new Point(0, 0), ApplySavedZoom = false };
        form.Shown += (_, _) =>
        {
            form.Bind(result);
            if (zoom != 1f) form.SetZoom(zoom, save: false);
            Application.DoEvents();
            var focus = result.Processes.Values.Where(p => p.Alerts.Count > 0)
                .OrderByDescending(p => p.MaxAlertLevel).ThenByDescending(p => p.Descendants().Count())
                .FirstOrDefault();
            for (int i = 0; i < form.Tabs.TabPages.Count; i++)
            {
                form.Tabs.SelectedIndex = i;
                Application.DoEvents();
                if (i == 1 && focus != null) form.TreeView.SelectInTree(focus, true);
                if (i == 2 && focus != null) form.TrackView.ShowProcess(focus);
                Application.DoEvents();
                using var bmp = new Bitmap(form.Width, form.Height);
                form.DrawToBitmap(bmp, new Rectangle(Point.Empty, form.Size));
                bmp.Save(Path.Combine(outDir, $"tab{i}.png"), ImageFormat.Png);
            }
            if (focus != null) form.TreeView.Graph.SaveImage(Path.Combine(outDir, "graph_full.png"));
            form.Close();
        };
        Application.Run(form);
        return 0;
    }
}

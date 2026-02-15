using System.Diagnostics;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Discord;
using Discord.WebSocket;

internal sealed class DealMonitorControlBot
{
	private readonly DiscordSocketClient _client;

	private readonly string _monitorDirectory;
	private readonly string _configPath;
	private readonly string _keywordsPath;

	private readonly ulong _channelId;
	private readonly HashSet<ulong> _allowedUserIds;
	private readonly bool _ack;
	private readonly string _tokenEnv;
	private int _scanRunning; // 0 = idle, 1 = running

	public DealMonitorControlBot(string monitorDirectory, string configPath, string keywordsPath, ulong channelId, IEnumerable<ulong> allowedUserIds, bool ack, string tokenEnv)
	{
		_monitorDirectory = monitorDirectory;
		_configPath = configPath;
		_keywordsPath = keywordsPath;
		_channelId = channelId;
		_allowedUserIds = new HashSet<ulong>(allowedUserIds);
		_ack = ack;
		_tokenEnv = tokenEnv;

		_client = new DiscordSocketClient(new DiscordSocketConfig
		{
			GatewayIntents = GatewayIntents.Guilds | GatewayIntents.GuildMessages | GatewayIntents.MessageContent,
			LogGatewayIntentWarnings = false,
			MessageCacheSize = 50
		});

		_client.Log += msg =>
		{
			Console.WriteLine($"[{DateTimeOffset.Now:yyyy-MM-dd HH:mm:ss}] [{msg.Severity}] {msg.Source}: {msg.Message} {msg.Exception}");
			return Task.CompletedTask;
		};

		_client.MessageReceived += OnMessageReceivedAsync;
	}

	public async Task RunAsync(CancellationToken cancellationToken)
	{
		var token = Environment.GetEnvironmentVariable(_tokenEnv);
		if (string.IsNullOrWhiteSpace(token))
		{
			Console.Error.WriteLine($"ERROR: Missing bot token. Set environment variable '{_tokenEnv}'.");
			Console.Error.WriteLine($"Example (PowerShell): $env:{_tokenEnv} = \"YOUR_TOKEN\"");
			return;
		}

		Console.WriteLine("Deal Monitor Control Bot starting...");
		Console.WriteLine($"Monitor dir: {_monitorDirectory}");
		Console.WriteLine($"Control channel: {_channelId}");
		Console.WriteLine($"Allowed users: {(_allowedUserIds.Count == 0 ? "(anyone)" : _allowedUserIds.Count.ToString())}");

		await _client.LoginAsync(TokenType.Bot, token.Trim());
		await _client.StartAsync();

		try
		{
			await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
		}
		catch (TaskCanceledException)
		{
			// shutdown
		}

		await _client.StopAsync();
		await _client.LogoutAsync();
	}

	private async Task OnMessageReceivedAsync(SocketMessage rawMessage)
	{
		if (rawMessage is not SocketUserMessage message)
		{
			return;
		}

		if (message.Author.IsBot)
		{
			return;
		}

		if (message.Channel is not SocketTextChannel textChannel)
		{
			return;
		}

		if (textChannel.Id != _channelId)
		{
			return;
		}

		if (_allowedUserIds.Count > 0 && !_allowedUserIds.Contains(message.Author.Id))
		{
			return;
		}

		var content = (message.Content ?? string.Empty).Trim();
		if (content.Length == 0)
		{
			return;
		}

		if (!content.StartsWith('!'))
		{
			return;
		}

		// Optional prefix: !dealmonitor <cmd>
		var cmdText = content;
		if (cmdText.StartsWith("!dealmonitor ", StringComparison.OrdinalIgnoreCase))
		{
			cmdText = "!" + cmdText["!dealmonitor ".Length..].TrimStart();
		}

		if (cmdText.Equals("!help", StringComparison.OrdinalIgnoreCase) || cmdText.Equals("!keywords help", StringComparison.OrdinalIgnoreCase))
		{
			await ReplyAsync(textChannel, BuildHelp());
			return;
		}

		if (cmdText.Equals("!keywords show", StringComparison.OrdinalIgnoreCase))
		{
			var keywords = LoadKeywords();
			await ReplyAsync(textChannel, $":information_source: Current keywords: {(keywords.Count == 0 ? "(none)" : string.Join(", ", keywords))}");
			return;
		}

		if (cmdText.Equals("!status", StringComparison.OrdinalIgnoreCase))
		{
			var keywords = LoadKeywords();
			var (maxPrice, minDiscount) = ReadFilters();
			var watches = ReadWatches();
			var watchPart = watches.Count > 0
				? $" | watches={watches.Count} ({string.Join(", ", watches.Select(w => w.Name))})"
				: "";
			await ReplyAsync(textChannel, $":information_source: Status | keywords={(keywords.Count == 0 ? "(none)" : string.Join(", ", keywords))} | max_price={maxPrice} | min_discount_percent={minDiscount}{watchPart}");
			return;
		}

		if (cmdText.StartsWith("!keywords set ", StringComparison.OrdinalIgnoreCase))
		{
			var raw = cmdText["!keywords set ".Length..];
			var keywords = raw
				.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
				.Where(k => !string.IsNullOrWhiteSpace(k))
				.Distinct(StringComparer.OrdinalIgnoreCase)
				.ToList();

			if (keywords.Count == 0)
			{
				await ReplyAsync(textChannel, ":warning: No keywords provided. Example: `!keywords set DDR5, 48GB, RAM`");
				return;
			}

			SaveKeywords(keywords);
			if (_ack)
			{
				await ReplyAsync(textChannel, $":white_check_mark: Updated keywords. Keywords: {string.Join(", ", keywords)}");
			}
			return;
		}

		if (cmdText.StartsWith("!maxprice ", StringComparison.OrdinalIgnoreCase))
		{
			var raw = cmdText["!maxprice ".Length..].Trim();
			if (!double.TryParse(raw, out var maxPrice) || maxPrice < 0)
			{
				await ReplyAsync(textChannel, ":warning: Invalid max price. Example: `!maxprice 200`");
				return;
			}

			WriteFilter("max_price", JsonValue.Create(maxPrice));
			if (_ack)
			{
				await ReplyAsync(textChannel, $":white_check_mark: Updated filter. max_price={maxPrice}");
			}
			return;
		}

		if (cmdText.StartsWith("!mindiscount ", StringComparison.OrdinalIgnoreCase))
		{
			var raw = cmdText["!mindiscount ".Length..].Trim();
			if (!int.TryParse(raw, out var minDiscount) || minDiscount < 0)
			{
				await ReplyAsync(textChannel, ":warning: Invalid min discount. Example: `!mindiscount 15`");
				return;
			}

			WriteFilter("min_discount_percent", JsonValue.Create(minDiscount));
			if (_ack)
			{
				await ReplyAsync(textChannel, $":white_check_mark: Updated filter. min_discount_percent={minDiscount}");
			}
			return;
		}

		if (cmdText.Equals("!ping", StringComparison.OrdinalIgnoreCase))
		{
			await ReplyAsync(textChannel, ":information_source: pong");
			return;
		}

		// ---- Watch commands ----
		if (cmdText.Equals("!watch list", StringComparison.OrdinalIgnoreCase))
		{
			var watches = ReadWatches();
			if (watches.Count == 0)
			{
				await ReplyAsync(textChannel, ":information_source: No watches configured. Use `!watch add Name | kw1, kw2 | max:500 | discount:15`");
			}
			else
			{
				var sb = new StringBuilder(":information_source: **Active watches:**\n");
				foreach (var w in watches)
				{
					var maxP = w.MaxPrice.HasValue ? w.MaxPrice.Value.ToString() : "any";
					var minD = w.MinDiscount.HasValue ? $"{w.MinDiscount.Value}%" : "any";
					sb.AppendLine($"- **{w.Name}**: keywords=[{string.Join(", ", w.Keywords)}] max_price={maxP} min_discount={minD}");
				}
				await ReplyAsync(textChannel, sb.ToString());
			}
			return;
		}

		if (cmdText.StartsWith("!watch add ", StringComparison.OrdinalIgnoreCase))
		{
			var raw = cmdText["!watch add ".Length..];
			var parts = raw.Split('|');
			if (parts.Length < 2)
			{
				await ReplyAsync(textChannel, ":warning: Format: `!watch add Name | kw1, kw2 | max:500 | discount:15`");
				return;
			}
			var watchName = parts[0].Trim();
			var watchKeywords = parts[1]
				.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
				.Where(k => !string.IsNullOrWhiteSpace(k))
				.ToList();
			if (string.IsNullOrWhiteSpace(watchName) || watchKeywords.Count == 0)
			{
				await ReplyAsync(textChannel, ":warning: Need a name and at least one keyword.");
				return;
			}
			double? watchMax = null;
			int? watchDiscount = null;
			for (var i = 2; i < parts.Length; i++)
			{
				var seg = parts[i].Trim();
				if (seg.StartsWith("max:", StringComparison.OrdinalIgnoreCase) &&
					double.TryParse(seg["max:".Length..].Trim(), out var mp))
					watchMax = mp;
				else if (seg.StartsWith("discount:", StringComparison.OrdinalIgnoreCase) &&
					int.TryParse(seg["discount:".Length..].Trim(), out var md))
					watchDiscount = md;
			}
			AddOrUpdateWatch(watchName, watchKeywords, watchMax, watchDiscount);
			var extras = "";
			if (watchMax.HasValue) extras += $", max: ${watchMax}";
			if (watchDiscount.HasValue) extras += $", discount: {watchDiscount}%";
			if (_ack)
				await ReplyAsync(textChannel, $":white_check_mark: Watch **{watchName}** added (keywords: {string.Join(", ", watchKeywords)}{extras})");
			return;
		}

		if (cmdText.StartsWith("!watch remove ", StringComparison.OrdinalIgnoreCase))
		{
			var watchName = cmdText["!watch remove ".Length..].Trim();
			var (removed, remaining) = RemoveWatch(watchName);
			if (removed)
				await ReplyAsync(textChannel, $":white_check_mark: Watch **{watchName}** removed. {remaining} watch(es) remaining.");
			else
				await ReplyAsync(textChannel, $":warning: Watch '{watchName}' not found.");
			return;
		}

		if (cmdText.Equals("!watch clear", StringComparison.OrdinalIgnoreCase))
		{
			ClearWatches();
			await ReplyAsync(textChannel, ":white_check_mark: All watches cleared.");
			return;
		}

		if (cmdText.Equals("!scan", StringComparison.OrdinalIgnoreCase))
		{
			await HandleScanAsync(textChannel);
			return;
		}

		if (cmdText.Equals("!clearhistory", StringComparison.OrdinalIgnoreCase))
		{
			await HandleClearHistoryAsync(textChannel);
			return;
		}
	}

	private async Task HandleClearHistoryAsync(ISocketMessageChannel channel)
	{
		try
		{
			var historyPath = Path.Combine(_monitorDirectory, "history.json");
			int count = 0;
			if (File.Exists(historyPath))
			{
				var content = File.ReadAllText(historyPath);
				if (JsonNode.Parse(content) is JsonArray arr)
					count = arr.Count;
			}
			WriteAtomic(historyPath, "[]");
			await ReplyAsync(channel, $":white_check_mark: History cleared ({count} deal{(count == 1 ? "" : "s")} removed). All deals will be treated as new on the next scan.");
		}
		catch (Exception ex)
		{
			await ReplyAsync(channel, $":x: Failed to clear history: {ex.Message}");
		}
	}

	private async Task HandleScanAsync(ISocketMessageChannel channel)
	{
		// Prevent concurrent scans
		if (Interlocked.CompareExchange(ref _scanRunning, 1, 0) != 0)
		{
			await ReplyAsync(channel, ":hourglass: A scan is already running. Please wait.");
			return;
		}

		try
		{
			await ReplyAsync(channel, ":mag: Scanning for deals now...");

			var scriptPath = Path.Combine(_monitorDirectory, "deal-monitor.ps1");
			if (!File.Exists(scriptPath))
			{
				await ReplyAsync(channel, ":x: deal-monitor.ps1 not found.");
				return;
			}

			var psi = new ProcessStartInfo
			{
				FileName = "powershell.exe",
				Arguments = $"-ExecutionPolicy Bypass -NoProfile -File \"{scriptPath}\" -SkipDiscordControl",
				WorkingDirectory = _monitorDirectory,
				RedirectStandardOutput = true,
				RedirectStandardError = true,
				UseShellExecute = false,
				CreateNoWindow = true
			};

			var stdout = new StringBuilder();
			var stderr = new StringBuilder();

			using var process = new Process { StartInfo = psi };
			process.OutputDataReceived += (_, e) => { if (e.Data != null) stdout.AppendLine(e.Data); };
			process.ErrorDataReceived += (_, e) => { if (e.Data != null) stderr.AppendLine(e.Data); };

			process.Start();
			process.BeginOutputReadLine();
			process.BeginErrorReadLine();

			// Timeout after 60 seconds
			var exited = await Task.Run(() => process.WaitForExit(60_000));
			if (!exited)
			{
				try { process.Kill(); } catch { /* best effort */ }
				await ReplyAsync(channel, ":x: Scan timed out after 60 seconds.");
				return;
			}

			// Parse output for the summary line
			var output = stdout.ToString();
			var lines = output.Split('\n', StringSplitOptions.RemoveEmptyEntries);

			// Find key info lines
			var sent = lines.FirstOrDefault(l => l.Contains("[SUCCESS] Sent:"));
			var filtered = lines.FirstOrDefault(l => l.Contains("Filtered deals (new):"));
			var total = lines.FirstOrDefault(l => l.Contains("Total deals fetched:"));
			var successLines = lines.Where(l => l.Contains("[SUCCESS] Discord notification sent:")).ToList();

			var sb = new StringBuilder();
			if (process.ExitCode == 0)
			{
				sb.AppendLine(":white_check_mark: **Scan complete!**");
				if (total != null)
				{
					var totalNum = ExtractNumber(total);
					sb.AppendLine($"Deals scanned: {totalNum}");
				}
				if (filtered != null)
				{
					var filteredNum = ExtractNumber(filtered);
					sb.AppendLine($"Matched: {filteredNum}");
				}
				if (sent != null)
				{
					var sentNum = ExtractNumber(sent);
					sb.AppendLine($"Notifications sent: {sentNum}");
				}
				if (successLines.Count > 0)
				{
					sb.AppendLine("**Deals found:**");
					foreach (var dealLine in successLines.Take(10))
					{
						// Extract just the deal title after "sent: "
						var idx = dealLine.IndexOf("sent:", StringComparison.Ordinal);
						var title = idx >= 0 ? dealLine[(idx + 5)..].Trim() : dealLine.Trim();
						sb.AppendLine($"- {title}");
					}
				}
				else
				{
					sb.AppendLine("No new deals found this scan.");
				}
			}
			else
			{
				sb.AppendLine($":x: Scan failed (exit code {process.ExitCode})");
				var errOutput = stderr.ToString().Trim();
				if (!string.IsNullOrEmpty(errOutput))
					sb.AppendLine($"```{errOutput[..Math.Min(errOutput.Length, 500)]}```");
			}

			await ReplyAsync(channel, sb.ToString());
		}
		catch (Exception ex)
		{
			await ReplyAsync(channel, $":x: Scan error: {ex.Message}");
		}
		finally
		{
			Interlocked.Exchange(ref _scanRunning, 0);
		}
	}

	private static string ExtractNumber(string line)
	{
		// Use the LAST number on the line to avoid picking up the year from timestamps like [2026-02-15 ...]
		var matches = System.Text.RegularExpressions.Regex.Matches(line, @"(\d+)");
		return matches.Count > 0 ? matches[matches.Count - 1].Groups[1].Value : "?";
	}

	private static string BuildHelp()
	{
		return string.Join("\n", new[]
		{
			":information_source: **Deal Monitor Bot — Command Reference**",
			"",
			"__**Keywords (simple mode)**__",
			"`!keywords set kw1, kw2, kw3` — Replace all keywords (comma-separated)",
			"`!keywords show` — Show current keywords from keywords.txt",
			"",
			"__**Watches (multi-search with per-group filters)**__",
			"`!watch add Name | kw1, kw2 | max:500 | discount:15`",
			"  ↳ Create/update a watch group. `max` and `discount` are optional.",
			"  ↳ Example: `!watch add GPU | 5080, 5070 ti | max:1200`",
			"`!watch list` — Show all active watches with their filters",
			"`!watch remove Name` — Delete a watch by name",
			"`!watch clear` — Remove all watches",
			"",
			"__**Global filters**__ (apply when no watch matches)",
			"`!maxprice 200` — Only notify for deals under this price",
			"`!mindiscount 15` — Only notify if discount ≥ this %",
			"",
			"__**On-demand**__",
			"`!scan` — Run the deal monitor right now (no waiting for schedule)",
			"`!clearhistory` — Reset seen-deals history so all deals re-send",
			"`!status` — Show current config (keywords, watches, filters)",
			"`!ping` — Check if bot is alive",
			"",
			"__**Notes**__",
			"• Keywords are **case-insensitive** (e.g., `1440p` matches `1440P`)",
			"• Watches take priority over simple keywords when both are set",
			"• Each watch has independent price/discount filters",
			"• `!scan` won't send duplicates — already-seen deals are skipped",
			"• Use `!clearhistory` + `!scan` to force re-check all deals"
		});
	}

	private List<string> LoadKeywords()
	{
		if (!File.Exists(_keywordsPath))
		{
			return new List<string>();
		}

		var lines = File.ReadAllLines(_keywordsPath);
		var keywords = new List<string>();
		foreach (var line in lines)
		{
			var trimmed = (line ?? string.Empty).Trim();
			if (trimmed.Length == 0)
			{
				continue;
			}
			if (trimmed.StartsWith('#'))
			{
				continue;
			}
			keywords.Add(trimmed);
		}
		return keywords.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
	}

	private void SaveKeywords(List<string> keywords)
	{
		Directory.CreateDirectory(Path.GetDirectoryName(_keywordsPath) ?? _monitorDirectory);
		var content = string.Join(Environment.NewLine, keywords);
		WriteAtomic(_keywordsPath, content);
	}

	private (string? maxPrice, string? minDiscount) ReadFilters()
	{
		try
		{
			var root = JsonNode.Parse(File.ReadAllText(_configPath)) as JsonObject;
			var filters = root?["filters"] as JsonObject;
			return (filters?["max_price"]?.ToJsonString(), filters?["min_discount_percent"]?.ToJsonString());
		}
		catch
		{
			return (null, null);
		}
	}

	// ---- Watch helpers ----

	private record WatchInfo(string Name, List<string> Keywords, double? MaxPrice, int? MinDiscount);

	private List<WatchInfo> ReadWatches()
	{
		try
		{
			var root = JsonNode.Parse(File.ReadAllText(_configPath)) as JsonObject;
			if (root?["watches"] is not JsonArray arr) return new();
			var result = new List<WatchInfo>();
			foreach (var node in arr)
			{
				if (node is not JsonObject obj) continue;
				var name = obj["name"]?.GetValue<string>() ?? "(unnamed)";
				var kws = new List<string>();
				if (obj["keywords"] is JsonArray kwArr)
					foreach (var k in kwArr)
						if (k?.GetValue<string>() is string s && !string.IsNullOrWhiteSpace(s))
							kws.Add(s);
				double? mp = obj["max_price"] is JsonNode mpn ? mpn.GetValue<double>() : null;
				int? md = obj["min_discount_percent"] is JsonNode mdn ? mdn.GetValue<int>() : null;
				result.Add(new WatchInfo(name, kws, mp, md));
			}
			return result;
		}
		catch { return new(); }
	}

	private void AddOrUpdateWatch(string name, List<string> keywords, double? maxPrice, int? minDiscount)
	{
		var root = (JsonNode.Parse(File.ReadAllText(_configPath)) as JsonObject) ?? new JsonObject();
		if (root["watches"] is not JsonArray watches)
		{
			watches = new JsonArray();
			root["watches"] = watches;
		}
		// Remove existing with same name
		for (var i = watches.Count - 1; i >= 0; i--)
		{
			if (watches[i] is JsonObject obj &&
				string.Equals(obj["name"]?.GetValue<string>(), name, StringComparison.OrdinalIgnoreCase))
				watches.RemoveAt(i);
		}
		var newWatch = new JsonObject
		{
			["name"] = name,
			["keywords"] = new JsonArray(keywords.Select(k => JsonValue.Create(k)).ToArray<JsonNode>())
		};
		if (maxPrice.HasValue) newWatch["max_price"] = maxPrice.Value;
		if (minDiscount.HasValue) newWatch["min_discount_percent"] = minDiscount.Value;
		watches.Add(newWatch);
		var json = root.ToJsonString(new JsonSerializerOptions { WriteIndented = true });
		WriteAtomic(_configPath, json);
	}

	private (bool removed, int remaining) RemoveWatch(string name)
	{
		var root = (JsonNode.Parse(File.ReadAllText(_configPath)) as JsonObject) ?? new JsonObject();
		if (root["watches"] is not JsonArray watches) return (false, 0);
		var found = false;
		for (var i = watches.Count - 1; i >= 0; i--)
		{
			if (watches[i] is JsonObject obj &&
				string.Equals(obj["name"]?.GetValue<string>(), name, StringComparison.OrdinalIgnoreCase))
			{
				watches.RemoveAt(i);
				found = true;
			}
		}
		if (!found) return (false, watches.Count);
		var json = root.ToJsonString(new JsonSerializerOptions { WriteIndented = true });
		WriteAtomic(_configPath, json);
		return (true, watches.Count);
	}

	private void ClearWatches()
	{
		var root = (JsonNode.Parse(File.ReadAllText(_configPath)) as JsonObject) ?? new JsonObject();
		root["watches"] = new JsonArray();
		var json = root.ToJsonString(new JsonSerializerOptions { WriteIndented = true });
		WriteAtomic(_configPath, json);
	}

	private void WriteFilter(string name, JsonNode value)
	{
		var root = (JsonNode.Parse(File.ReadAllText(_configPath)) as JsonObject) ?? new JsonObject();
		var filters = root["filters"] as JsonObject;
		if (filters is null)
		{
			filters = new JsonObject();
			root["filters"] = filters;
		}
		filters[name] = value;
		var json = root.ToJsonString(new JsonSerializerOptions { WriteIndented = true });
		WriteAtomic(_configPath, json);
	}

	private static void WriteAtomic(string path, string content)
	{
		var tmp = path + ".tmp";
		File.WriteAllText(tmp, content, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
		File.Copy(tmp, path, overwrite: true);
		File.Delete(tmp);
	}

	private static async Task ReplyAsync(ISocketMessageChannel channel, string message)
	{
		// Discord max message length is 2000; keep responses short.
		if (message.Length > 1900)
		{
			message = message[..1900] + "...";
		}
		await channel.SendMessageAsync(message, allowedMentions: AllowedMentions.None);
	}

	public static (string monitorDirectory, string configPath, string keywordsPath) ResolvePaths()
	{
		var fromEnv = Environment.GetEnvironmentVariable("DEAL_MONITOR_DIR");
		if (!string.IsNullOrWhiteSpace(fromEnv) && Directory.Exists(fromEnv))
		{
			var cfg = Path.Combine(fromEnv, "config.json");
			var kw = Path.Combine(fromEnv, "keywords.txt");
			return (fromEnv, cfg, kw);
		}

		// Prefer working directory (user can set Start In for Task Scheduler / service)
		var cwd = Directory.GetCurrentDirectory();
		var cfgCwd = Path.Combine(cwd, "config.json");
		if (File.Exists(cfgCwd))
		{
			return (cwd, cfgCwd, Path.Combine(cwd, "keywords.txt"));
		}

		// Fallback: search upwards from base directory
		var dir = AppContext.BaseDirectory;
		for (var i = 0; i < 6; i++)
		{
			var cfg = Path.Combine(dir, "config.json");
			if (File.Exists(cfg))
			{
				return (dir, cfg, Path.Combine(dir, "keywords.txt"));
			}
			var parent = Directory.GetParent(dir);
			if (parent is null)
			{
				break;
			}
			dir = parent.FullName;
		}

		throw new FileNotFoundException("Could not locate config.json. Set DEAL_MONITOR_DIR or run the bot with working directory set to the deal-monitor folder.");
	}
}

internal static class Program
{
	public static async Task Main()
	{
		var cts = new CancellationTokenSource();
		Console.CancelKeyPress += (_, e) =>
		{
			e.Cancel = true;
			cts.Cancel();
		};

		var (monitorDir, configPath, keywordsPath) = DealMonitorControlBot.ResolvePaths();

		var configJson = File.ReadAllText(configPath);
		var root = JsonNode.Parse(configJson) as JsonObject ?? throw new InvalidOperationException("Invalid config.json");
		var discordControl = root["discord_control"] as JsonObject ?? throw new InvalidOperationException("Missing discord_control in config.json");

		var enabled = discordControl["enabled"]?.GetValue<bool>() ?? false;
		if (!enabled)
		{
			Console.Error.WriteLine("ERROR: discord_control.enabled is false. Set it to true in config.json.");
			return;
		}

		var channelIdStr = discordControl["channel_id"]?.GetValue<string>() ?? string.Empty;
		if (!ulong.TryParse(channelIdStr, out var channelId) || channelId == 0)
		{
			Console.Error.WriteLine("ERROR: discord_control.channel_id is missing/invalid in config.json.");
			return;
		}

		var tokenEnv = discordControl["token_env"]?.GetValue<string>() ?? "DISCORD_BOT_TOKEN";
		var ack = discordControl["ack"]?.GetValue<bool>() ?? true;

		var allowed = new List<ulong>();
		if (discordControl["allowed_user_ids"] is JsonArray allowArr)
		{
			foreach (var n in allowArr)
			{
				var s = n?.GetValue<string>();
				if (ulong.TryParse(s, out var id))
				{
					allowed.Add(id);
				}
			}
		}

		var bot = new DealMonitorControlBot(monitorDir, configPath, keywordsPath, channelId, allowed, ack, tokenEnv);
		await bot.RunAsync(cts.Token);
	}
}

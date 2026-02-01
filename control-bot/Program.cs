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
			await ReplyAsync(textChannel, $":information_source: Status | keywords={(keywords.Count == 0 ? "(none)" : string.Join(", ", keywords))} | max_price={maxPrice} | min_discount_percent={minDiscount}");
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
	}

	private static string BuildHelp()
	{
		return string.Join("\n", new[]
		{
			":information_source: Deal Monitor control commands:",
			"- !keywords set kw1, kw2, kw3   (comma-separated)",
			"- !keywords show",
			"- !maxprice 200",
			"- !mindiscount 15",
			"- !status",
			"- !ping",
			"Tip: you can also prefix with `!dealmonitor` (example: `!dealmonitor status`)"
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

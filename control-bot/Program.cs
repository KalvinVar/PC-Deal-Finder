using System.Diagnostics;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
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
	private CancellationTokenSource? _autoScanCts;

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
		_client.Ready += RegisterSlashCommandsAsync;
		_client.SlashCommandExecuted += OnSlashCommandExecutedAsync;
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

		var initialInterval = ReadScanIntervalMinutes();
		if (initialInterval > 0)
		{
			StartAutoScanLoop(initialInterval);
			Console.WriteLine($"[{DateTimeOffset.Now:yyyy-MM-dd HH:mm:ss}] [INFO] Auto-scan loop started (every {initialInterval} min)");
		}

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

		// Alias: !dealtype is the user-facing name for !flairs — now removed, show helpful redirect
		if (cmdText.StartsWith("!dealtype", StringComparison.OrdinalIgnoreCase) ||
		    cmdText.StartsWith("!flairs", StringComparison.OrdinalIgnoreCase))
		{
			await ReplyAsync(textChannel, ":information_source: Deal type filtering is now per-watch. Use `!watch add GPU | 5080 | max:1200 | type:GPU` to add a type filter to a watch.");
			return;
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
			var watches = ReadWatches();
			var flairs = ReadFlairs();
			var interval = ReadScanIntervalMinutes();
			var histCount = 0;
			try { var hp = Path.Combine(_monitorDirectory, "history.json"); if (File.Exists(hp) && JsonNode.Parse(File.ReadAllText(hp)) is JsonArray ha) histCount = ha.Count; } catch { }
			var sb2 = new StringBuilder(":information_source: **Status**\n");
			if (watches.Count > 0)
				sb2.AppendLine($"**Watches:** {string.Join(" | ", watches.Select(w => $"{w.Name} [{string.Join(", ", w.Keywords)}]{(w.MaxPrice.HasValue ? $" max=${w.MaxPrice}" : "")}{(w.MinDiscount.HasValue ? $" discount={w.MinDiscount}%" : "")}"))}");
			else
				sb2.AppendLine("**Watches:** (none)");
			var kwStr2 = keywords.Count == 0 ? "(none)" : string.Join(", ", keywords);
			sb2.AppendLine(keywords.Count > 0 && watches.Count > 0
				? $"**Keywords (keywords.txt):** {kwStr2} \u26a0\ufe0f ignored \u2014 watches take priority"
				: $"**Keywords:** {kwStr2}");
			sb2.AppendLine($"**Deal type filter:** {(flairs.Count == 0 ? "(all types)" : string.Join(", ", flairs))}");
			sb2.AppendLine($"**History:** {histCount} deal{(histCount == 1 ? "" : "s")} seen");
			sb2.AppendLine($"**Auto-scan:** {(interval > 0 ? $"every {FormatInterval(interval)}" : "off")}");
			await ReplyAsync(textChannel, sb2.ToString());
			return;
		}

		if (cmdText.StartsWith("!keywords set ", StringComparison.OrdinalIgnoreCase))
		{
			var raw = cmdText["!keywords set ".Length..];
			var keywords = raw
				.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
				.Where(k => !string.IsNullOrWhiteSpace(k))
				.Select(NormalizeKeyword)
				.Where(k => k.Length > 0)
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

		if (cmdText.StartsWith("!keywords add ", StringComparison.OrdinalIgnoreCase))
		{
			var raw = cmdText["!keywords add ".Length..];
			var toAdd = raw
				.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
				.Where(k => !string.IsNullOrWhiteSpace(k))
				.Select(NormalizeKeyword)
				.Where(k => k.Length > 0)
				.Distinct(StringComparer.OrdinalIgnoreCase)
				.ToList();

			if (toAdd.Count == 0)
			{
				await ReplyAsync(textChannel, ":warning: No keywords provided. Example: `!keywords add RTX 5070, 4K monitor`");
				return;
			}

			var existing = LoadKeywords();
			var merged = existing.Concat(toAdd).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
			var added = toAdd.Where(k => !existing.Any(e => string.Equals(e, k, StringComparison.OrdinalIgnoreCase))).ToList();
			SaveKeywords(merged);
			if (_ack)
			{
				var msg = added.Count > 0
					? $":white_check_mark: Added: **{string.Join(", ", added)}**. All keywords: {string.Join(", ", merged)}"
					: $":information_source: Keywords already present — no change. All: {string.Join(", ", merged)}";
				await ReplyAsync(textChannel, msg);
			}
			return;
		}

		if (cmdText.StartsWith("!keywords remove ", StringComparison.OrdinalIgnoreCase))
		{
			var raw = cmdText["!keywords remove ".Length..];
			var toRemove = raw
				.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
				.Where(k => !string.IsNullOrWhiteSpace(k))
				.Distinct(StringComparer.OrdinalIgnoreCase)
				.ToList();

			if (toRemove.Count == 0)
			{
				await ReplyAsync(textChannel, ":warning: Specify keyword(s) to remove. Example: `!keywords remove DDR5, RAM`");
				return;
			}

			var existing = LoadKeywords();
			var remaining = existing
				.Where(k => !toRemove.Any(r => string.Equals(r, k, StringComparison.OrdinalIgnoreCase)))
				.ToList();
			var removedCount = existing.Count - remaining.Count;
			SaveKeywords(remaining);
			if (_ack)
			{
				var msg = removedCount > 0
					? $":white_check_mark: Removed {removedCount} keyword{(removedCount == 1 ? "" : "s")}. Remaining: {(remaining.Count == 0 ? "(none)" : string.Join(", ", remaining))}"
					: $":information_source: None of those keywords matched. Current: {(existing.Count == 0 ? "(none)" : string.Join(", ", existing))}";
				await ReplyAsync(textChannel, msg);
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

		if (cmdText.Equals("!flairs show", StringComparison.OrdinalIgnoreCase))
		{
			var flairs = ReadFlairs();
			await ReplyAsync(textChannel, $":information_source: Category filter: {(flairs.Count == 0 ? "(none — all categories accepted)" : string.Join(", ", flairs))}");
			return;
		}

		if (cmdText.StartsWith("!flairs set ", StringComparison.OrdinalIgnoreCase))
		{
			var raw = cmdText["!flairs set ".Length..];
			var flairs = raw
				.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
				.Where(f => !string.IsNullOrWhiteSpace(f))
				.Distinct(StringComparer.OrdinalIgnoreCase)
				.ToList();
			WriteFlairs(flairs.Count > 0 ? flairs : null);
			if (_ack)
				await ReplyAsync(textChannel, $":white_check_mark: Category filter set to: {(flairs.Count == 0 ? "(all accepted)" : string.Join(", ", flairs))}");
			return;
		}

		if (cmdText.StartsWith("!flairs add ", StringComparison.OrdinalIgnoreCase))
		{
			var raw = cmdText["!flairs add ".Length..];
			var toAdd = raw
				.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
				.Where(f => !string.IsNullOrWhiteSpace(f))
				.ToList();
			if (toAdd.Count == 0)
			{
				await ReplyAsync(textChannel, ":warning: No categories provided. Example: `!flairs add SSD, Monitor`");
				return;
			}
			var existing = ReadFlairs();
			var merged = existing.Concat(toAdd).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
			WriteFlairs(merged);
			if (_ack)
				await ReplyAsync(textChannel, $":white_check_mark: Category filter updated: {string.Join(", ", merged)}");
			return;
		}

		if (cmdText.Equals("!flairs clear", StringComparison.OrdinalIgnoreCase))
		{
			WriteFlairs(null);
			if (_ack)
				await ReplyAsync(textChannel, ":white_check_mark: Category filter cleared — all post categories will be accepted.");
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
				.Select(NormalizeKeyword)
				.Where(k => k.Length > 0)
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

		if (cmdText.Equals("!history count", StringComparison.OrdinalIgnoreCase) ||
		    cmdText.Equals("!history", StringComparison.OrdinalIgnoreCase))
		{
			var histPath = Path.Combine(_monitorDirectory, "history.json");
			try
			{
				if (!File.Exists(histPath))
				{
					await ReplyAsync(textChannel, ":information_source: No history file found (0 tracked deals).");
					return;
				}
				var histContent = File.ReadAllText(histPath);
				var count = JsonNode.Parse(histContent) is JsonArray arr ? arr.Count : 0;
				await ReplyAsync(textChannel, $":information_source: History: **{count}** deal{(count == 1 ? "" : "s")} tracked. Use `!clearhistory` to reset.");
			}
			catch (Exception ex)
			{
				await ReplyAsync(textChannel, $":x: Could not read history: {ex.Message}");
			}
			return;
		}

		if (cmdText.StartsWith("!scaninterval", StringComparison.OrdinalIgnoreCase))
		{
			var arg = cmdText["!scaninterval".Length..].Trim();
			if (arg.Equals("off", StringComparison.OrdinalIgnoreCase))
			{
				StopAutoScanLoop();
				WriteScanIntervalMinutes(null);
				if (_ack)
					await ReplyAsync(textChannel, ":white_check_mark: Auto-scan disabled. Use `!scan` to scan manually.");
				return;
			}
			if (!int.TryParse(arg, out var intervalMin) || intervalMin < 1)
			{
				var current = ReadScanIntervalMinutes();
				var currentStr = current > 0 ? $"currently {current} min" : "currently off";
				await ReplyAsync(textChannel, $":warning: Usage: `!scaninterval 30` (minutes ≥ 1) or `!scaninterval off`. {currentStr}.");
				return;
			}
			WriteScanIntervalMinutes(intervalMin);
			StartAutoScanLoop(intervalMin);
			if (_ack)
				await ReplyAsync(textChannel, $":white_check_mark: Auto-scan set to every **{intervalMin} minute{(intervalMin == 1 ? "" : "s")}**. Next scan in ~{intervalMin} min.");
			return;
		}
	}

	private async Task RegisterSlashCommandsAsync()
	{
		try
		{
			var channel = _client.GetChannel(_channelId) as SocketGuildChannel;
			var guild = channel?.Guild;
			if (guild is null)
			{
				Console.WriteLine($"[{DateTimeOffset.Now:yyyy-MM-dd HH:mm:ss}] [WARNING] Cannot register slash commands: channel {_channelId} not found or not a guild channel.");
				return;
			}

			var commands = new List<Discord.ApplicationCommandProperties>
			{
				new SlashCommandBuilder()
					.WithName("watch")
					.WithDescription("Watch groups — monitor products with their own keywords, price limit, and optional deal type")
					.AddOption(new SlashCommandOptionBuilder()
						.WithName("list").WithDescription("Show all watch groups and their filters")
						.WithType(ApplicationCommandOptionType.SubCommand))
					.AddOption(new SlashCommandOptionBuilder()
						.WithName("add").WithDescription("Create or update a watch group")
						.WithType(ApplicationCommandOptionType.SubCommand)
						.AddOption("name", ApplicationCommandOptionType.String, "Label for this group, e.g. GPU or SSD", isRequired: true)
						.AddOption("keywords", ApplicationCommandOptionType.String, "Words to match, e.g. RTX 5080, 5070 Ti", isRequired: true)
						.AddOption("maxprice", ApplicationCommandOptionType.Number, "Only notify at or below this price, e.g. 800", isRequired: false)
						.AddOption("discount", ApplicationCommandOptionType.Integer, "Minimum discount %, e.g. 10", isRequired: false)
						.AddOption("type", ApplicationCommandOptionType.String, "Only match posts with this Reddit flair, e.g. GPU or Monitor", isRequired: false))
					.AddOption(new SlashCommandOptionBuilder()
						.WithName("remove").WithDescription("Delete a watch group by its name")
						.WithType(ApplicationCommandOptionType.SubCommand)
						.AddOption("name", ApplicationCommandOptionType.String, "Name of the group to delete", isRequired: true))
					.AddOption(new SlashCommandOptionBuilder()
						.WithName("clear").WithDescription("Delete all watch groups at once")
						.WithType(ApplicationCommandOptionType.SubCommand))
					.Build(),

				new SlashCommandBuilder()
					.WithName("scan")
					.WithDescription("Check for new deals right now instead of waiting for the next scheduled run")
					.Build(),

				new SlashCommandBuilder()
					.WithName("scaninterval")
					.WithDescription("Auto-scan every N days/minutes (bot must stay running). Use 'off' to disable.")
					.AddOption("days", ApplicationCommandOptionType.Integer, "Number of days between scans (e.g. 1)", isRequired: false)
					.AddOption("minutes", ApplicationCommandOptionType.Integer, "Additional minutes on top of days (e.g. 30)", isRequired: false)
					.AddOption("off", ApplicationCommandOptionType.Boolean, "Set to True to disable auto-scanning", isRequired: false)
					.Build(),

				new SlashCommandBuilder()
					.WithName("clearhistory")
					.WithDescription("Forget all previously seen deals so they can be re-sent on the next scan")
					.Build(),

				new SlashCommandBuilder()
					.WithName("status")
					.WithDescription("Show a summary of all current settings: keywords, filters, watches, and scan interval")
					.Build(),

				new SlashCommandBuilder()
					.WithName("ping")
					.WithDescription("Check that the bot is online and responding")
					.Build(),
			};

			await guild.BulkOverwriteApplicationCommandAsync(commands.ToArray());
			Console.WriteLine($"[{DateTimeOffset.Now:yyyy-MM-dd HH:mm:ss}] [INFO] Registered {commands.Count} slash command(s) to guild '{guild.Name}'.");
		}
		catch (Exception ex)
		{
			Console.WriteLine($"[{DateTimeOffset.Now:yyyy-MM-dd HH:mm:ss}] [ERROR] Failed to register slash commands: {ex.Message}");
		}
	}

	private async Task OnSlashCommandExecutedAsync(SocketSlashCommand command)
	{
		// Only handle commands in the designated control channel
		if (command.Channel.Id != _channelId)
			return;

		// Enforce allowed-user allowlist
		if (_allowedUserIds.Count > 0 && !_allowedUserIds.Contains(command.User.Id))
		{
			await command.RespondAsync(":no_entry: You are not authorized to use this command.", ephemeral: true);
			return;
		}

		var name = command.CommandName;
		// First-level option is either the value (top-level command) or a subcommand
		var first = command.Data.Options.FirstOrDefault();
		var subName = first?.Type == ApplicationCommandOptionType.SubCommand ? first.Name : "";

		string reply;
		switch (name)
		{
			case "ping":
				await command.RespondAsync(":information_source: pong");
				return;

			case "status":
			{
				var keywords = LoadKeywords();
				var watches = ReadWatches();
				var flairs = ReadFlairs();
				var interval = ReadScanIntervalMinutes();
				var histCount = 0;
				try { var hp = Path.Combine(_monitorDirectory, "history.json"); if (File.Exists(hp) && JsonNode.Parse(File.ReadAllText(hp)) is JsonArray ha) histCount = ha.Count; } catch { }
				var sbS = new StringBuilder(":information_source: **Status**\n");
				if (watches.Count > 0)
				{
					sbS.AppendLine($"**Watches:**");
					foreach (var w in watches)
					{
						var maxStr = w.MaxPrice.HasValue ? $" max=${w.MaxPrice}" : "";
						var discStr = w.MinDiscount.HasValue ? $" discount={w.MinDiscount}%" : "";
						var typeStr = w.Flairs.Count > 0 ? $" type={string.Join(",", w.Flairs)}" : "";
						sbS.AppendLine($"  {w.Name} [{string.Join(", ", w.Keywords)}]{maxStr}{discStr}{typeStr}");
					}
				}
				else
					sbS.AppendLine("**Watches:** (none)");
				var kwStrS = keywords.Count == 0 ? "(none)" : string.Join(", ", keywords);
			sbS.AppendLine(keywords.Count > 0 && watches.Count > 0
				? $"**Keywords (keywords.txt):** {kwStrS} \u26a0\ufe0f ignored \u2014 watches take priority"
				: $"**Keywords:** {kwStrS}");
			sbS.AppendLine($"**History:** {histCount} deal{(histCount == 1 ? "" : "s")} seen");
			sbS.AppendLine($"**Auto-scan:** {(interval > 0 ? $"every {FormatInterval(interval)}" : "off")}");
				reply = sbS.ToString();
				if (reply.Length > 1900) reply = reply[..1900] + "...";
				await command.RespondAsync(reply);
				return;
			}



			case "clearhistory":
			{
				try
				{
					var histPath = Path.Combine(_monitorDirectory, "history.json");
					var count = File.Exists(histPath) && JsonNode.Parse(File.ReadAllText(histPath)) is JsonArray arr ? arr.Count : 0;
					WriteAtomic(histPath, "[]");
					await command.RespondAsync($":white_check_mark: History cleared ({count} deal{(count == 1 ? "" : "s")} removed). All deals will be treated as new on the next scan.");
				}
				catch (Exception ex) { await command.RespondAsync($":x: Failed to clear history: {ex.Message}"); }
				return;
			}



			case "scaninterval":
			{
				var val = ((string)(first?.Value ?? "")).Trim();
				if (val.Equals("off", StringComparison.OrdinalIgnoreCase))
				{
					StopAutoScanLoop();
					WriteScanIntervalMinutes(null);
					await command.RespondAsync(":white_check_mark: Auto-scan disabled. Use `/scan` to scan manually.");
					return;
				}
				if (!int.TryParse(val, out var mins) || mins < 1)
				{
					var cur = ReadScanIntervalMinutes();
					await command.RespondAsync($":warning: Provide a number ≥ 1 or `off`. Currently: {(cur > 0 ? $"{cur} min" : "off")}.");
					return;
				}
				WriteScanIntervalMinutes(mins);
				StartAutoScanLoop(mins);
				await command.RespondAsync($":white_check_mark: Auto-scan every **{mins} minute{(mins == 1 ? "" : "s")}**. Next scan in ~{mins} min.");
				return;
			}

			// /scan uses DeferAsync because the PS process can take >3 seconds
			case "scan":
			{
				if (Interlocked.CompareExchange(ref _scanRunning, 1, 0) != 0)
				{
					await command.RespondAsync(":hourglass: A scan is already running. Please wait.");
					return;
				}
				await command.DeferAsync(); // acknowledge within 3 s; result comes via FollowupAsync
				try
				{
					var scriptPath = Path.Combine(_monitorDirectory, "deal-monitor.ps1");
					if (!File.Exists(scriptPath)) { await command.FollowupAsync(":x: deal-monitor.ps1 not found."); return; }

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
					var exited = await Task.Run(() => process.WaitForExit(60_000));
					if (!exited) { try { process.Kill(); } catch { } await command.FollowupAsync(":x: Scan timed out after 60 seconds."); return; }

					var lines = stdout.ToString().Split('\n', StringSplitOptions.RemoveEmptyEntries);
					var sent = lines.FirstOrDefault(l => l.Contains("[SUCCESS] Sent:"));
					var filtered = lines.FirstOrDefault(l => l.Contains("Filtered deals (new):"));
					var total = lines.FirstOrDefault(l => l.Contains("Total deals fetched:"));
					var successLines = lines.Where(l => l.Contains("[SUCCESS] Discord notification sent:")).ToList();
					var sb = new StringBuilder();
					if (process.ExitCode == 0)
					{
						sb.AppendLine(":white_check_mark: **Scan complete!**");
						if (total != null) sb.AppendLine($"Deals scanned: {ExtractNumber(total)}");
						if (filtered != null) sb.AppendLine($"Matched: {ExtractNumber(filtered)}");
						if (sent != null) sb.AppendLine($"Notifications sent: {ExtractNumber(sent)}");
						if (successLines.Count > 0) { sb.AppendLine("**Deals found:**"); foreach (var dl in successLines.Take(10)) { var idx = dl.IndexOf("sent:", StringComparison.Ordinal); sb.AppendLine($"- {(idx >= 0 ? dl[(idx + 5)..].Trim() : dl.Trim())}"); } }
						else sb.AppendLine("No new deals found this scan.");
					}
					else
					{
						sb.AppendLine($":x: Scan failed (exit code {process.ExitCode})");
						var errOut = stderr.ToString().Trim();
						if (!string.IsNullOrEmpty(errOut)) sb.AppendLine($"```{errOut[..Math.Min(errOut.Length, 500)]}```");
					}
					var result = sb.ToString();
					if (result.Length > 1900) result = result[..1900] + "...";
					await command.FollowupAsync(result);
				}
				finally { Interlocked.Exchange(ref _scanRunning, 0); }
				return;
			}



			case "watch":
			{
				var subOpts = first?.Options ?? Enumerable.Empty<SocketSlashCommandDataOption>();
				switch (subName)
				{
					case "list":
					{
						var watches = ReadWatches();
						if (watches.Count == 0) { await command.RespondAsync(":information_source: No watches configured."); return; }
						var sb = new StringBuilder(":information_source: **Active watches:**\n");
						foreach (var w in watches)
						{
							var maxP = w.MaxPrice.HasValue ? w.MaxPrice.Value.ToString() : "any";
							var minD = w.MinDiscount.HasValue ? $"{w.MinDiscount.Value}%" : "any";
							sb.AppendLine($"- **{w.Name}**: [{string.Join(", ", w.Keywords)}] max={maxP} discount={minD}");
						}
						reply = sb.ToString();
						if (reply.Length > 1900) reply = reply[..1900] + "...";
						await command.RespondAsync(reply);
						return;
					}
					case "add":
					{
						var opts = subOpts.ToDictionary(o => o.Name);
						var wName = NormalizeKeyword((string)(opts["name"].Value ?? ""));
						var kwRaw = (string)(opts["keywords"].Value ?? "");
						var kws = kwRaw.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
							.Select(NormalizeKeyword).Where(k => k.Length > 0).ToList();
						if (string.IsNullOrWhiteSpace(wName) || kws.Count == 0) { await command.RespondAsync(":warning: Need a name and at least one keyword."); return; }
						double? mp = opts.TryGetValue("maxprice", out var mpOpt) ? Convert.ToDouble(mpOpt.Value) : null;
						int? md = opts.TryGetValue("discount", out var mdOpt) ? Convert.ToInt32(mdOpt.Value) : null;
						var wfl = opts.TryGetValue("type", out var typeOpt)
							? ((string)(typeOpt.Value ?? "")).Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).ToList()
							: new List<string>();
						AddOrUpdateWatch(wName, kws, mp, md, wfl.Count > 0 ? wfl : null);
						var extras = (mp.HasValue ? $", max: ${mp}" : "") + (md.HasValue ? $", discount: {md}%" : "") + (wfl.Count > 0 ? $", type: {string.Join(",", wfl)}" : "");
						await command.RespondAsync($":white_check_mark: Watch **{wName}** saved (keywords: {string.Join(", ", kws)}{extras}).");
						return;
					}
					case "remove":
					{
						var wName = (string)(subOpts.First().Value ?? "");
						var (removed, remaining) = RemoveWatch(wName);
						await command.RespondAsync(removed
							? $":white_check_mark: Watch **{wName}** removed. {remaining} watch(es) remaining."
							: $":warning: Watch '{wName}' not found.");
						return;
					}
					case "clear":
						ClearWatches();
						await command.RespondAsync(":white_check_mark: All watches cleared.");
						return;
				}
				break;
			}

		}

		await command.RespondAsync(":warning: Unknown or malformed command.", ephemeral: true);
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
			"__**Keywords**__ — words the bot looks for in deal titles",
			"`!keywords set kw1, kw2` — replace the entire list",
			"`!keywords add kw1, kw2` — add to the existing list",
			"`!keywords remove kw1` — remove a specific word",
			"`!keywords show` — see what the bot is currently watching",
			"",
			"__**Watches**__ — separate keyword groups each with their own price limit",
			"`!watch add GPU | RTX 5080, 5070 Ti | max:1200 | discount:10`",
			"`!watch list` — see all watch groups",
			"`!watch remove GPU` — delete a watch group",
			"`!watch clear` — delete all watch groups",
			"",
			"__**Filters**__ — global limits applied when no watch group matches",
			"`!maxprice 200` — skip deals over this price",
			"`!mindiscount 15` — skip deals with less than this % off",
			"`!flairs set GPU, SSD` — only notify for these deal categories",
			"`!flairs add Monitor` — add a category to the filter",
			"`!flairs show` — see active category filters",
			"`!flairs clear` — notify for all categories again",
			"",
			"__**Scanning**__",
			"`!scan` — check for deals right now",
			"`!scaninterval 2d` / `!scaninterval 30` / `!scaninterval 1d 30` — auto-scan interval",
			"`!scaninterval off` — stop auto-scanning",
			"",
			"__**History & Status**__",
			"`!history` — how many deals have been seen",
			"`!clearhistory` — forget seen deals so they can re-send",
			"`!status` — see a full summary of all current settings",
			"`!ping` — check if the bot is online",
			"",
			"**Tips**",
			"• Keywords are case-insensitive — `RTX` and `rtx` both work",
			"• Extra spaces and leading zeros are auto-cleaned (e.g. `050W` → `50W`)",
			"• Watch groups take priority over simple keywords when both are set",
			"• `!scan` won't re-send deals already in history",
			"• Use `!clearhistory` then `!scan` to force a full re-check"
		});
	}

	/// <summary>
	/// Normalizes a keyword: collapses whitespace and strips leading zeros from
	/// embedded numbers so that e.g. "050W" becomes "50W" and "01440p" becomes "1440p".
	/// This prevents accidental mismatches caused by formatting differences.
	/// </summary>
	private static string NormalizeKeyword(string kw)
	{
		// 1. Trim and collapse internal whitespace
		kw = Regex.Replace(kw.Trim(), @"\s+", " ");
		// 2. Strip leading zeros from numbers embedded in text (e.g. "050W" → "50W")
		kw = Regex.Replace(kw, @"\b0+(\d)", "$1");
		return kw;
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

	private List<string> ReadFlairs()
	{
		try
		{
			var root = JsonNode.Parse(File.ReadAllText(_configPath)) as JsonObject;
			var filters = root?["filters"] as JsonObject;
			if (filters?["flairs"] is JsonArray arr)
				return arr
					.Select(n => n?.GetValue<string>() ?? "")
					.Where(s => !string.IsNullOrWhiteSpace(s))
					.ToList();
			return new();
		}
		catch { return new(); }
	}

	private void WriteFlairs(List<string>? flairs)
	{
		var root = (JsonNode.Parse(File.ReadAllText(_configPath)) as JsonObject) ?? new JsonObject();
		var filters = root["filters"] as JsonObject;
		if (filters is null)
		{
			filters = new JsonObject();
			root["filters"] = filters;
		}
		if (flairs == null || flairs.Count == 0)
			filters["flairs"] = null;
		else
			filters["flairs"] = new JsonArray(flairs.Select(f => JsonValue.Create(f)).ToArray<JsonNode>());
		var json = root.ToJsonString(new JsonSerializerOptions { WriteIndented = true });
		WriteAtomic(_configPath, json);
	}

	private static string FormatInterval(int totalMinutes)
	{
		if (totalMinutes <= 0) return "off";
		var d = totalMinutes / 1440;
		var m = totalMinutes % 1440;
		if (d > 0 && m > 0) return $"{d} day{(d == 1 ? "" : "s")} {m} min";
		if (d > 0) return $"{d} day{(d == 1 ? "" : "s")}";
		return $"{m} min";
	}

	private int ReadScanIntervalMinutes()
	{
		try
		{
			var root = JsonNode.Parse(File.ReadAllText(_configPath)) as JsonObject;
			if (root?["scan_interval_minutes"] is JsonNode n)
			{
				var v = n.GetValue<int>();
				if (v > 0) return v;
			}
			return 0;
		}
		catch { return 0; }
	}

	private void WriteScanIntervalMinutes(int? minutes)
	{
		var root = (JsonNode.Parse(File.ReadAllText(_configPath)) as JsonObject) ?? new JsonObject();
		if (minutes.HasValue && minutes.Value > 0)
			root["scan_interval_minutes"] = minutes.Value;
		else
			root.Remove("scan_interval_minutes");
		var json = root.ToJsonString(new JsonSerializerOptions { WriteIndented = true });
		WriteAtomic(_configPath, json);
	}

	private void StartAutoScanLoop(int minutes)
	{
		// Cancel any existing loop
		_autoScanCts?.Cancel();
		_autoScanCts = new CancellationTokenSource();
		var token = _autoScanCts.Token;

		_ = Task.Run(async () =>
		{
			while (!token.IsCancellationRequested)
			{
				try
				{
					await Task.Delay(TimeSpan.FromMinutes(minutes), token);
				}
				catch (OperationCanceledException)
				{
					break;
				}

				if (token.IsCancellationRequested)
					break;

				if (_client.GetChannel(_channelId) is ISocketMessageChannel chan)
				{
					Console.WriteLine($"[{DateTimeOffset.Now:yyyy-MM-dd HH:mm:ss}] [INFO] Auto-scan triggered (interval: {minutes} min)");
					await HandleScanAsync(chan);
				}
			}
		}, CancellationToken.None);
	}

	private void StopAutoScanLoop()
	{
		_autoScanCts?.Cancel();
		_autoScanCts = null;
	}

	// ---- Watch helpers ----

	private record WatchInfo(string Name, List<string> Keywords, double? MaxPrice, int? MinDiscount, List<string> Flairs);

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
				var flairs = new List<string>();
				if (obj["flairs"] is JsonArray fArr)
					foreach (var f in fArr)
						if (f?.GetValue<string>() is string fs && !string.IsNullOrWhiteSpace(fs))
							flairs.Add(fs);
				result.Add(new WatchInfo(name, kws, mp, md, flairs));
			}
			return result;
		}
		catch { return new(); }
	}

	private void AddOrUpdateWatch(string name, List<string> keywords, double? maxPrice, int? minDiscount, List<string>? flairs = null)
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
		if (flairs != null && flairs.Count > 0)
			newWatch["flairs"] = new JsonArray(flairs.Select(f => JsonValue.Create(f)).ToArray<JsonNode>());
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


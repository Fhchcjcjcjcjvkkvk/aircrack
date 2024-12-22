import discord
from discord.ext import commands
import yfinance as yf
import csv
import os

# Intents (required for Discord bots)
intents = discord.Intents.default()
intents.message_content = True

# Bot prefix and initialization
bot = commands.Bot(command_prefix="!", intents=intents)

@bot.event
async def on_ready():
    print(f"Bot is ready as {bot.user}")

@bot.command()
async def usage(ctx, ticker: str, option: str = "max"):
    """
    Command to fetch financial data from Yahoo Finance and save as CSV.
    Usage: !usage <ticker> <option>
    Example: !usage GOOG max
    """
    try:
        # Fetch data from Yahoo Finance
        stock = yf.Ticker(ticker)
        hist = stock.history(period=option)

        if hist.empty:
            await ctx.send(f"No data found for {ticker} with option {option}.")
            return

        # Save data to CSV
        filename = f"{ticker}_{option}.csv"
        hist.to_csv(filename)

        # Send file to Discord
        await ctx.send(f"Here is the data for {ticker} ({option}):", file=discord.File(filename))

        # Remove file after sending
        os.remove(filename)
    except Exception as e:
        await ctx.send(f"An error occurred: {e}")

@bot.command()
async def earnings(ctx, ticker: str):
    """
    Command to fetch earnings data from Yahoo Finance.
    Usage: !earnings <ticker>
    Example: !earnings GOOG
    """
    try:
        # Fetch earnings data from Yahoo Finance
        stock = yf.Ticker(ticker)
        earnings = stock.earnings

        if earnings is None:
            await ctx.send(f"No earnings data found for {ticker}.")
            return

        # Format the earnings data
        earnings_info = f"Earnings data for {ticker}:\n"
        for date, data in earnings.items():
            earnings_info += f"Date: {date}, EPS: {data['EPS']}, Revenue: {data['Revenue']}\n"

        # Send the earnings data to Discord
        await ctx.send(earnings_info)

    except Exception as e:
        await ctx.send(f"An error occurred: {e}")

# Run the bot (replace 'YOUR_BOT_TOKEN' with your bot token)
bot.run('MTI2NzA3MTA5NTY3NzI1NTY4MA.GfH8aG.j6h9WuKVo9W2Rp3MF-hh95OBzBZZ6zZbYH8uAA')

"""
Jnvoy Slack Connector
Protects every AI bot message in your Slack workspace.

When a user sends a message to an AI bot, Jnvoy intercepts it,
scans for PII, redacts sensitive data, forwards the clean message
to the LLM, and posts the response back to Slack with a
compliance note showing what was protected.

Setup:
1. Create a Slack app at api.slack.com/apps
2. Add bot scopes: chat:write, channels:history, app_mentions:read,
   im:history, im:write, channels:read
3. Install to workspace and copy the Bot Token
4. Copy the Signing Secret from Basic Information
5. Set environment variables:
   SLACK_BOT_TOKEN=xoxb-your-token
   SLACK_SIGNING_SECRET=your-signing-secret
   ANTHROPIC_API_KEY=your-anthropic-key
6. Run: python connectors/slack_connector.py

How it works:
User mentions @Jnvoy or sends a DM
        ↓
Jnvoy scans message for PII
        ↓
Redacts sensitive data locally
        ↓
Forwards clean message to Claude
        ↓
Posts response back to Slack
        ↓
Adds compliance thread note
"""

import os
import sys
sys.path.insert(0, "/Users/jeevannagaraj/Desktop/jnvoy")

from dotenv import load_dotenv
from pathlib import Path
load_dotenv("/Users/jeevannagaraj/Desktop/jnvoy/.env")

from slack_bolt import App
from slack_bolt.adapter.socket_mode import SocketModeHandler
import anthropic

from core.detector import PIIDetector

# Initialise the PII detector
detector = PIIDetector(use_ner=True)

# Initialise Anthropic client
anthropic_client = anthropic.Anthropic(
    api_key=os.environ.get("ANTHROPIC_API_KEY")
)

# Initialise Slack app
app = App(
    token=os.environ.get("SLACK_BOT_TOKEN"),
    signing_secret=os.environ.get("SLACK_SIGNING_SECRET")
)


def format_pii_summary(summary: dict) -> str:
    """Format PII detection results into a human readable message."""
    if not summary:
        return "No sensitive data detected."

    items = []
    type_names = {
        "EMAIL": "email address",
        "PHONE_UK": "UK phone number",
        "PHONE_INTL": "international phone number",
        "CREDIT_CARD": "credit card number",
        "NHS_NUMBER": "NHS number",
        "NI_NUMBER": "National Insurance number",
        "UK_POSTCODE": "UK postcode",
        "DATE_OF_BIRTH": "date of birth",
        "IP_ADDRESS": "IP address",
        "SORT_CODE": "sort code",
        "ACCOUNT_NUMBER": "account number",
        "PASSPORT": "passport number",
        "API_KEY": "API key",
        "SECRET_TOKEN": "secret token",
        "NER_PERSON": "person name",
        "NER_ORG": "organisation name",
        "NER_GPE": "location",
        "NER_LOC": "location",
    }

    for pii_type, count in summary.items():
        name = type_names.get(pii_type, pii_type.lower().replace("_", " "))
        items.append(f"{count} {name}{'s' if count > 1 else ''}")

    return ", ".join(items)


def call_claude(message: str) -> str:
    """Send a message to Claude and return the response."""
    try:
        response = anthropic_client.messages.create(
            model="claude-haiku-4-5-20251001",
            max_tokens=1000,
            messages=[{"role": "user", "content": message}]
        )
        return response.content[0].text
    except Exception as e:
        return f"Sorry, I could not process your request: {str(e)}"


def process_message(message_text: str) -> dict:
    """
    Core Jnvoy processing pipeline.
    1. Detect PII
    2. Redact sensitive data
    3. Send clean message to Claude
    4. Return response with audit info
    """
    # Step 1: Detect and redact PII
    detection_result = detector.detect(message_text)

    # Step 2: Send clean message to Claude
    llm_response = call_claude(detection_result.redacted_text)

    # Step 3: Restore original values in response
    restored_response = detector.restore(llm_response, detection_result.token_map)

    return {
        "response": restored_response,
        "pii_detected": detection_result.pii_found,
        "pii_summary": detection_result.summary,
        "total_pii_instances": len(detection_result.matches),
        "redacted_text": detection_result.redacted_text,
    }


# ─── Slack Event Handlers ──────────────────────────────────────────────────────

@app.event("app_mention")
def handle_mention(event, say, client):
    """
    Handle when someone mentions @Jnvoy in a channel.
    Processes the message through the PII firewall and responds.
    """
    # Remove the bot mention from the message
    text = event.get("text", "")
    # Strip the mention tag <@BOTID>
    import re
    clean_text = re.sub(r"<@[A-Z0-9]+>", "", text).strip()

    if not clean_text:
        say("Hi! Send me a message and I will protect it before sending to AI.")
        return

    # Process through Jnvoy
    result = process_message(clean_text)

    # Post the AI response
    say(result["response"])

    # Add compliance note in thread if PII was detected
    if result["pii_detected"]:
        pii_description = format_pii_summary(result["pii_summary"])
        client.chat_postMessage(
            channel=event["channel"],
            thread_ts=event["ts"],
            text=(
                f"🛡️ *Jnvoy Privacy Protection*\n"
                f"Detected and redacted: {pii_description}\n"
                f"Sensitive data was *not* transmitted to the AI.\n"
                f"_Protected by Jnvoy — jnvoy.onrender.com_"
            )
        )


@app.event("message")
def handle_dm(event, say, client):
    """
    Handle direct messages to the Jnvoy bot.
    Only processes DMs not channel messages to avoid double processing.
    """
    # Only handle DMs (channel_type im means direct message)
    if event.get("channel_type") != "im":
        return

    # Ignore bot messages to prevent loops
    if event.get("bot_id"):
        return

    text = event.get("text", "").strip()
    if not text:
        return

    # Process through Jnvoy
    result = process_message(text)

    # Post the AI response
    say(result["response"])

    # Always show protection status in DMs
    if result["pii_detected"]:
        pii_description = format_pii_summary(result["pii_summary"])
        say(
            f"🛡️ *Jnvoy protected your message*\n"
            f"Detected and redacted: {pii_description}\n"
            f"This data was *not* sent to the AI."
        )
    else:
        say("✅ *Jnvoy scan complete* — No sensitive data detected.")


@app.event("app_home_opened")
def handle_home_opened(event, client):
    """
    Show a welcome screen when someone opens the Jnvoy app home tab.
    """
    client.views_publish(
        user_id=event["user"],
        view={
            "type": "home",
            "blocks": [
                {
                    "type": "header",
                    "text": {
                        "type": "plain_text",
                        "text": "🛡️ Jnvoy AI Privacy Firewall"
                    }
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": "*Protecting your AI conversations from data leakage.*\n\nJnvoy automatically detects and redacts sensitive data before it reaches any AI model."
                    }
                },
                {
                    "type": "divider"
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": "*How to use Jnvoy:*\n• Send a DM to @Jnvoy with any message\n• Mention @Jnvoy in any channel\n• Jnvoy will protect your message and respond"
                    }
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": "*What Jnvoy protects:*\n• Email addresses\n• Phone numbers\n• Credit card numbers\n• National Insurance numbers\n• NHS numbers\n• Passport numbers\n• API keys and tokens\n• Person names and organisations"
                    }
                },
                {
                    "type": "divider"
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": "Live API: jnvoy.onrender.com\nGitHub: github.com/Jeevan2191999/jnvoy"
                    }
                }
            ]
        }
    )


# ─── Main ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("Starting Jnvoy Slack Connector...")
    print("Listening for messages...")

    # Socket Mode allows local development without a public URL
    # For production deployment use HTTP mode with a public URL
    app_token = os.environ.get("SLACK_APP_TOKEN")
    if app_token:
        handler = SocketModeHandler(app, app_token)
        handler.start()
    else:
        print("No SLACK_APP_TOKEN found.")
        print("For local testing add SLACK_APP_TOKEN to your .env file.")
        print("Get it from api.slack.com/apps > Your App > Basic Information > App-Level Tokens")
        print("Create a token with connections:write scope")

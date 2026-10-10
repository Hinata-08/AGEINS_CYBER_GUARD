/**
 * AGEINS Cyber AI Assistant (ShieldBot)
 * Bilingual (English + Hinglish) Cyber Copilot Client
 */

const CHAT_API_URL = `${window.AGEINS_API_BASE || "http://127.0.0.1:8001"}/api/chat`;

function initChatbot() {
    // Check if chatbot HTML is already injected
    if (document.getElementById("ageins-chatbot-container")) return;

    const chatContainer = document.createElement("div");
    chatContainer.id = "ageins-chatbot-container";
    chatContainer.innerHTML = `
        <!-- Floating Launcher Button -->
        <div class="chatbot-launcher" id="chatLauncher" title="Talk to AGEINS AI Cyber Assistant">
            🤖
        </div>

        <!-- Chatbot Window -->
        <div class="chatbot-modal hidden" id="chatModal">
            <div class="chatbot-header">
                <div class="chat-bot-identity">
                    <div class="chat-avatar">🛡️</div>
                    <div>
                        <h4>AGEINS ShieldBot</h4>
                        <span><span class="pulse-dot"></span> Cyber AI Active</span>
                    </div>
                </div>
                <button class="chat-close-btn" id="chatCloseBtn">&times;</button>
            </div>

            <!-- Message Area -->
            <div class="chat-messages" id="chatMessages">
                <div class="chat-bubble bot">
                    Namaste! Main <strong>AGEINS AI Cyber Assistant</strong> hoon. Aap mujhse fraud threats, phishing links, deepfake image/video/audio detection, ya scam hone par emergency steps ke baare me pooch sakte hain.
                </div>
            </div>

            <!-- Quick Suggested Prompts -->
            <div class="suggested-prompts-bar" id="chatSuggestedPrompts">
                <span class="prompt-chip" onclick="sendQuickPrompt('Kya ye link safe hai?')">🔗 Check suspicious link</span>
                <span class="prompt-chip" onclick="sendQuickPrompt('Deepfake video kaise pehchane?')">🎭 Deepfake indicators</span>
                <span class="prompt-chip" onclick="sendQuickPrompt('Scam ho gaya, ab kya karein?')">🚨 Emergency 1930</span>
                <span class="prompt-chip" onclick="sendQuickPrompt('Mera data safe hai kya?')">🛡️ Data Privacy</span>
            </div>

            <!-- Input Area -->
            <div class="chat-input-area">
                <input type="text" id="chatInput" class="chat-input" placeholder="Ask in Hindi / English, or paste link..." onkeydown="handleChatKeyDown(event)">
                <button class="chat-send-btn" id="chatSendBtn" onclick="sendChatMessage()">➤</button>
            </div>
        </div>
    `;

    document.body.appendChild(chatContainer);

    // Event Listeners
    document.getElementById("chatLauncher").addEventListener("click", toggleChatModal);
    document.getElementById("chatCloseBtn").addEventListener("click", toggleChatModal);
}

function toggleChatModal() {
    const modal = document.getElementById("chatModal");
    modal.classList.toggle("hidden");
    if (!modal.classList.contains("hidden")) {
        document.getElementById("chatInput").focus();
    }
}

function handleChatKeyDown(event) {
    if (event.key === "Enter") {
        sendChatMessage();
    }
}

function sendQuickPrompt(promptText) {
    const input = document.getElementById("chatInput");
    input.value = promptText;
    sendChatMessage();
}

async function sendChatMessage() {
    const input = document.getElementById("chatInput");
    const messageContainer = document.getElementById("chatMessages");
    const text = input.value.trim();

    if (!text) return;

    // Append user message bubble
    const userBubble = document.createElement("div");
    userBubble.className = "chat-bubble user";
    userBubble.textContent = text;
    messageContainer.appendChild(userBubble);
    input.value = "";
    messageContainer.scrollTop = messageContainer.scrollHeight;

    // Append bot loading bubble
    const botLoading = document.createElement("div");
    botLoading.className = "chat-bubble bot";
    botLoading.id = "bot-typing-indicator";
    botLoading.innerHTML = `<span class="loader-spinner" style="width:14px;height:14px;border-width:2px;vertical-align:middle;margin-right:6px;"></span> AGEINS AI is thinking...`;
    messageContainer.appendChild(botLoading);
    messageContainer.scrollTop = messageContainer.scrollHeight;

    try {
        const response = await fetch(CHAT_API_URL, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ message: text, user_id: "user@ageins.cyber" })
        });

        if (!response.ok) throw new Error("Server error");
        const data = await response.json();

        botLoading.remove();

        const botReplyBubble = document.createElement("div");
        botReplyBubble.className = "chat-bubble bot";
        
        // Format markdown: bold, newlines, links
        let formatted = data.reply
            .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
            .replace(/\*(.*?)\*/g, '<em>$1</em>')
            .replace(/`(.*?)`/g, '<code style="background:#050d18;padding:2px 5px;border-radius:4px;color:#19e6a0;">$1</code>')
            .replace(/\[(.*?)\]\((.*?)\)/g, '<a href="$2" target="_blank" style="color:#00d2ff;text-decoration:underline;">$1</a>')
            .replace(/\n/g, '<br>');

        botReplyBubble.innerHTML = formatted;
        messageContainer.appendChild(botReplyBubble);

        // Update suggested prompts if provided
        if (data.suggested_actions && data.suggested_actions.length > 0) {
            const promptsBar = document.getElementById("chatSuggestedPrompts");
            promptsBar.innerHTML = "";
            data.suggested_actions.forEach(action => {
                const chip = document.createElement("span");
                chip.className = "prompt-chip";
                chip.textContent = action;
                chip.onclick = () => sendQuickPrompt(action);
                promptsBar.appendChild(chip);
            });
        }
    } catch (err) {
        botLoading.remove();
        const errorBubble = document.createElement("div");
        errorBubble.className = "chat-bubble bot";
        errorBubble.innerHTML = `⚠️ <strong>Connection Issue</strong>: Make sure backend is running on <code>http://127.0.0.1:8001</code>.<br><br>🚨 <strong>Emergency Tip</strong>: Fraud hone par call <strong>1930</strong> (National Cyber Crime Helpline) ya visit <strong>cybercrime.gov.in</strong>.`;
        messageContainer.appendChild(errorBubble);
    } finally {
        messageContainer.scrollTop = messageContainer.scrollHeight;
    }
}

// Auto-initialize when document loads
if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", initChatbot);
} else {
    initChatbot();
}

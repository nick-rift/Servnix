import { Anthropic } from '@anthropic-ai/sdk';
import logger from '../utils/logger.js';
import fs from 'fs';

const client = new Anthropic({
  apiKey: process.env.CLAUDE_API_KEY
});

const aiThreatDetection = {
  conversationHistory: [],
  threatPatterns: [],
  maxHistoryLength: 50,

  async analyzeSecurityEvent(event) {
    try {
      if (!process.env.CLAUDE_API_KEY) {
        logger.warn('Claude API key not configured - AI threat detection disabled');
        return { analysis: 'AI disabled', recommendation: 'Configure CLAUDE_API_KEY' };
      }

      const systemPrompt = `Du bist ein AI-Sicherheitsexperte für Enterprise-Server. Analysiere Sicherheitsereignisse und gib Empfehlungen.
      
Deine Aufgaben:
1. Erkenne Angriffsmuster und Anomalien
2. Bewerte das Bedrohungsniveau (LOW, MEDIUM, HIGH, CRITICAL)
3. Gib sofortige Handlungsempfehlungen
4. Erkenne Botnet/Malware-Aktivitäten
5. Blockiere verdächtige IPs automatisch

Sei präzise, technisch und schnell.`;

      // Kurze Event-Beschreibung für Claude
      const eventSummary = `
Event: ${event.eventType}
Daten: ${JSON.stringify(event.data)}
Zeitstempel: ${new Date().toISOString()}

Analysiere dieses Sicherheitsereignis und gib sofortige Empfehlung.`;

      // Conversation für Kontext
      this.conversationHistory.push({
        role: 'user',
        content: eventSummary
      });

      // Limit history
      if (this.conversationHistory.length > this.maxHistoryLength) {
        this.conversationHistory = this.conversationHistory.slice(-this.maxHistoryLength);
      }

      const response = await client.messages.create({
        model: 'claude-3-5-sonnet-20241022',
        max_tokens: 500,
        system: systemPrompt,
        messages: this.conversationHistory
      });

      const aiResponse = response.content[0].type === 'text' ? response.content[0].text : '';

      // Speichere AI-Antwort in History
      this.conversationHistory.push({
        role: 'assistant',
        content: aiResponse
      });

      // Parse Bedrohungslevel und Aktion
      const threatLevel = this.extractThreatLevel(aiResponse);
      const actionRequired = this.extractAction(aiResponse, threatLevel);

      logger.info(`[AI THREAT ANALYSIS] Threat Level: ${threatLevel}`, { event, aiResponse });

      return {
        analysis: aiResponse,
        threatLevel: threatLevel,
        actionRequired: actionRequired,
        timestamp: new Date().toISOString(),
        aiModel: 'Claude 3.5 Sonnet'
      };
    } catch (error) {
      logger.error('AI analysis error:', error);
      return {
        analysis: 'Error during AI analysis',
        error: error.message,
        threatLevel: 'UNKNOWN'
      };
    }
  },

  extractThreatLevel(response) {
    const lowerResponse = response.toLowerCase();
    if (lowerResponse.includes('critical') || lowerResponse.includes('sofortige blockade')) return 'CRITICAL';
    if (lowerResponse.includes('high') || lowerResponse.includes('hohe priorität')) return 'HIGH';
    if (lowerResponse.includes('medium')) return 'MEDIUM';
    return 'LOW';
  },

  extractAction(response, threatLevel) {
    if (threatLevel === 'CRITICAL') {
      return {
        action: 'BLOCK_IMMEDIATE',
        description: 'Sofortiges Blocken erforderlich',
        autoExecute: true
      };
    }
    if (threatLevel === 'HIGH') {
      return {
        action: 'ISOLATE_MONITOR',
        description: 'Isolieren und überwachen',
        autoExecute: false
      };
    }
    return {
      action: 'MONITOR',
      description: 'Weiter überwachen',
      autoExecute: false
    };
  },

  async learnFromPattern(pattern) {
    this.threatPatterns.push({
      pattern: pattern,
      timestamp: new Date().toISOString(),
      occurrences: 1
    });

    // Keep last 100 patterns
    if (this.threatPatterns.length > 100) {
      this.threatPatterns = this.threatPatterns.slice(-100);
    }

    logger.info(`[AI LEARNING] Learned threat pattern: ${JSON.stringify(pattern)}`);
  },

  getConversationContext() {
    return {
      totalMessages: this.conversationHistory.length,
      learnedPatterns: this.threatPatterns.length,
      lastAnalysis: this.conversationHistory.length > 0 ? this.conversationHistory[this.conversationHistory.length - 1] : null
    };
  }
};

export default aiThreatDetection;

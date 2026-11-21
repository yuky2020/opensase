// Package saas is the built-in catalog of well-known SaaS applications (ADR-0017). The
// Control Plane uses it to turn a tenant's SaaS policy (block apps or whole categories) into
// DNS blocklists in the Policy Snapshot. Devices and Edges then enforce it on DNS answers, and
// the Edge also enforces it on the TLS SNI or HTTP Host of each flow. The Control Plane also
// tags flow records with the app their hostname belongs to (discovery).
//
// The catalog only names applications and the domains they are served from. It is
// deliberately small and conservative: a domain is listed only if it belongs to one app.
package saas

import (
	"slices"
	"strings"
)

// App is one SaaS application.
type App struct {
	ID       string
	Name     string
	Category string
	// Domains are registrable domains or hostnames; each matches itself and its subdomains.
	Domains []string
}

// Categories of the catalog.
const (
	CatFileSharing   = "file-sharing"
	CatWebmail       = "webmail"
	CatAIAssistant   = "ai-assistant"
	CatSocialMedia   = "social-media"
	CatMessaging     = "messaging"
	CatCollaboration = "collaboration"
	CatStreaming     = "streaming"
	CatCodeHosting   = "code-hosting"
)

var catalog = []App{
	// File sharing and cloud storage.
	{"dropbox", "Dropbox", CatFileSharing, []string{"dropbox.com", "dropboxusercontent.com", "db.tt"}},
	{"google-drive", "Google Drive", CatFileSharing, []string{"drive.google.com", "drive.usercontent.google.com"}},
	{"onedrive", "OneDrive", CatFileSharing, []string{"onedrive.live.com", "onedrive.com", "1drv.ms", "1drv.com"}},
	{"box", "Box", CatFileSharing, []string{"box.com", "boxcloud.com"}},
	{"wetransfer", "WeTransfer", CatFileSharing, []string{"wetransfer.com", "we.tl"}},
	{"mega", "MEGA", CatFileSharing, []string{"mega.nz", "mega.io", "mega.co.nz"}},
	{"pcloud", "pCloud", CatFileSharing, []string{"pcloud.com"}},
	{"icloud", "iCloud", CatFileSharing, []string{"icloud.com", "icloud-content.com"}},

	// Webmail.
	{"gmail", "Gmail", CatWebmail, []string{"mail.google.com"}},
	{"outlook-web", "Outlook on the web", CatWebmail, []string{"outlook.live.com", "outlook.office.com", "outlook.office365.com"}},
	{"yahoo-mail", "Yahoo Mail", CatWebmail, []string{"mail.yahoo.com"}},
	{"proton-mail", "Proton Mail", CatWebmail, []string{"mail.proton.me", "protonmail.com"}},
	{"zoho-mail", "Zoho Mail", CatWebmail, []string{"mail.zoho.com", "mail.zoho.eu"}},

	// AI assistants.
	{"chatgpt", "ChatGPT", CatAIAssistant, []string{"chatgpt.com", "chat.openai.com"}},
	{"claude", "Claude", CatAIAssistant, []string{"claude.ai"}},
	{"gemini", "Gemini", CatAIAssistant, []string{"gemini.google.com"}},
	{"copilot", "Microsoft Copilot", CatAIAssistant, []string{"copilot.microsoft.com"}},
	{"perplexity", "Perplexity", CatAIAssistant, []string{"perplexity.ai"}},
	{"le-chat", "Le Chat", CatAIAssistant, []string{"chat.mistral.ai"}},
	{"deepseek", "DeepSeek", CatAIAssistant, []string{"deepseek.com"}},

	// Social media.
	{"facebook", "Facebook", CatSocialMedia, []string{"facebook.com", "fb.com", "fbcdn.net"}},
	{"instagram", "Instagram", CatSocialMedia, []string{"instagram.com", "cdninstagram.com"}},
	{"x", "X (Twitter)", CatSocialMedia, []string{"x.com", "twitter.com", "twimg.com"}},
	{"tiktok", "TikTok", CatSocialMedia, []string{"tiktok.com", "tiktokcdn.com", "tiktokv.com"}},
	{"linkedin", "LinkedIn", CatSocialMedia, []string{"linkedin.com", "licdn.com"}},
	{"reddit", "Reddit", CatSocialMedia, []string{"reddit.com", "redd.it", "redditmedia.com"}},
	{"snapchat", "Snapchat", CatSocialMedia, []string{"snapchat.com"}},

	// Messaging.
	{"whatsapp", "WhatsApp", CatMessaging, []string{"whatsapp.com", "whatsapp.net"}},
	{"telegram", "Telegram", CatMessaging, []string{"telegram.org", "t.me"}},
	{"discord", "Discord", CatMessaging, []string{"discord.com", "discord.gg", "discordapp.com"}},

	// Collaboration.
	{"slack", "Slack", CatCollaboration, []string{"slack.com", "slack-edge.com"}},
	{"teams", "Microsoft Teams", CatCollaboration, []string{"teams.microsoft.com", "teams.live.com"}},
	{"zoom", "Zoom", CatCollaboration, []string{"zoom.us", "zoom.com"}},
	{"notion", "Notion", CatCollaboration, []string{"notion.so", "notion.site"}},
	{"trello", "Trello", CatCollaboration, []string{"trello.com"}},
	{"google-docs", "Google Docs", CatCollaboration, []string{"docs.google.com"}},

	// Streaming.
	{"youtube", "YouTube", CatStreaming, []string{"youtube.com", "youtu.be", "googlevideo.com", "ytimg.com"}},
	{"netflix", "Netflix", CatStreaming, []string{"netflix.com", "nflxvideo.net"}},
	{"twitch", "Twitch", CatStreaming, []string{"twitch.tv", "ttvnw.net"}},
	{"spotify", "Spotify", CatStreaming, []string{"spotify.com", "scdn.co"}},

	// Code hosting and paste sites.
	{"github", "GitHub", CatCodeHosting, []string{"github.com", "githubusercontent.com"}},
	{"gitlab", "GitLab", CatCodeHosting, []string{"gitlab.com"}},
	{"bitbucket", "Bitbucket", CatCodeHosting, []string{"bitbucket.org"}},
	{"pastebin", "Pastebin", CatCodeHosting, []string{"pastebin.com"}},
}

var (
	byID     = map[string]int{}
	byDomain = map[string]int{}
)

func init() {
	for i, a := range catalog {
		if _, dup := byID[a.ID]; dup {
			panic("saas: duplicate app " + a.ID)
		}
		byID[a.ID] = i
		for _, d := range a.Domains {
			if _, dup := byDomain[d]; dup {
				panic("saas: domain in two apps: " + d)
			}
			byDomain[d] = i
		}
	}
}

// Apps returns a copy of the catalog, sorted by category then name.
func Apps() []App {
	out := make([]App, len(catalog))
	for i, a := range catalog {
		a.Domains = slices.Clone(a.Domains)
		out[i] = a
	}
	slices.SortFunc(out, func(a, b App) int {
		if c := strings.Compare(a.Category, b.Category); c != 0 {
			return c
		}
		return strings.Compare(a.Name, b.Name)
	})
	return out
}

// Categories returns the category names, sorted.
func Categories() []string {
	var out []string
	for _, a := range catalog {
		if !slices.Contains(out, a.Category) {
			out = append(out, a.Category)
		}
	}
	slices.Sort(out)
	return out
}

// ByID returns the app with the given ID.
func ByID(id string) (App, bool) {
	i, ok := byID[id]
	if !ok {
		return App{}, false
	}
	return catalog[i], true
}

// IsCategory reports whether c is a catalog category.
func IsCategory(c string) bool { return slices.Contains(Categories(), c) }

// Lookup returns the app that serves host (lowercase, no trailing dot): the longest catalog
// domain equal to host or a parent of it.
func Lookup(host string) (App, bool) {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	for h := host; h != ""; {
		if i, ok := byDomain[h]; ok {
			return catalog[i], true
		}
		dot := strings.IndexByte(h, '.')
		if dot < 0 {
			break
		}
		h = h[dot+1:]
	}
	return App{}, false
}

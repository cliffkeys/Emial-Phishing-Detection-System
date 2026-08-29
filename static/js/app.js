/**
 * MailShield - Email Spam & Phishing Detection System
 * Academic Project Client JavaScript
 */

document.addEventListener('DOMContentLoaded', () => {
    // Auto-dismiss alert banners after 5 seconds
    const alerts = document.querySelectorAll('.alert-dismissible');
    alerts.forEach(alert => {
        setTimeout(() => {
            const bsAlert = bootstrap.Alert.getOrCreateInstance(alert);
            if (bsAlert) {
                bsAlert.close();
            }
        }, 6000);
    });

    // Preset Sample Email Templates for Academic Defense Demo
    const demoSamples = {
        legit_meeting: {
            mode: 'form',
            sender: 'sarah.connor@cyberdyne-enterprise.com',
            recipient: 'engineering-team@cyberdyne-enterprise.com',
            subject: 'Sprint Retrospective & Q3 Milestone Review - Friday 2 PM',
            body: 'Hi Team,\n\nPlease join us this Friday at 2:00 PM in Conference Room B (or via Google Meet) for our sprint retrospective.\n\nAgenda:\n1. Sprint 44 Deliverables Review\n2. Q3 Resource Planning & Budget Allocation\n3. Architecture migration roadmap\n\nMeeting link: https://meet.google.com/abc-defg-hij\n\nBest regards,\nSarah Connor\nEngineering Lead',
            attachments: 'Q3_Sprint_Roadmap.pdf'
        },
        promo_spam: {
            mode: 'form',
            sender: 'promotions@global-mega-deals-online.biz',
            recipient: 'user@example.com',
            subject: 'CONGRATULATIONS! You Won $1,000,000 in International Sweepstakes!',
            body: 'DEAR BENEFICIARY,\n\nYOU HAVE BEEN SELECTED AS THE LUCKY WINNER OF 1,000,000 DOLLARS IN OUR GLOBAL EMAIL LOTTERY! CLAIM YOUR CASH PRIZE IMMEDIATELY!\n\n100% Guaranteed approval! No credit check required!\nClick here to claim your reward: http://cheap-sweepstakes-lottery.xyz/claim?id=99281\n\nAlso check out our miracle weight loss pills and 90% discount designer luxury watches!',
            attachments: ''
        },
        ms_phishing: {
            mode: 'form',
            sender: 'Microsoft Security Team <security-alert@microsoft-support-auth.xyz>',
            recipient: 'employee@corporate.com',
            subject: 'URGENT: Your Office 365 Account Will Be Suspended Within 24 Hours',
            body: 'Dear Valued User,\n\nWe detected unauthorized sign-in attempts on your Microsoft 365 mailbox from an unknown IP address.\n\nYour account access will be deactivated immediately unless you verify your password credentials within 24 hours.\n\nPlease sign in to verify your identity and restore mailbox access:\nhttp://login-microsoft-secure-auth.xyz/verify?user=employee\n\nIT Support Services\nMicrosoft Corporation',
            attachments: ''
        },
        paypal_spoof: {
            mode: 'form',
            sender: 'PayPal Service Desk <billing-update@paypal-account-center.top>',
            recipient: 'customer@gmail.com',
            subject: 'Security Notice: Your PayPal Account Has Been Restricted',
            body: 'We have temporarily limited your PayPal account due to suspicious billing activity.\n\nTo restore full account functionality, verify your debit/credit card details and security questions now:\nhttp://192.168.1.105/paypal-auth/resolution.php\n\nFailure to verify will lead to permanent account suspension.',
            attachments: ''
        },
        malware_invoice: {
            mode: 'form',
            sender: 'Accounting Dept <invoicing@supplier-billing.com>',
            recipient: 'finance@company.com',
            subject: 'Overdue Remittance Notice: Invoice #INV-89218 Attached',
            body: 'Dear Customer,\n\nPlease find attached the overdue payment invoice #INV-89218 for immediate processing.\n\nFailure to remit payment within 48 hours will incur late penalties. Please review the attached breakdown.\n\nRegards,\nAccounts Receivable',
            attachments: 'Invoice_Overdue_August2026.pdf.exe'
        },
        raw_rfc: {
            mode: 'raw',
            raw_email: `From: "Apple Security Support" <service-appleid@security-verify-apple.club>
To: target.user@domain.com
Subject: Critical Security Warning: Apple ID Password Reset Required
Date: Sat, 29 Aug 2026 09:15:00 +0000
Message-ID: <8492019482.apple.alert@security-verify-apple.club>
MIME-Version: 1.0
Content-Type: text/html; charset=UTF-8
Authentication-Results: spf=fail (sender IP is not authorized); dkim=fail; dmarc=fail

<html>
<body>
<h3>Dear Customer,</h3>
<p>Your Apple ID was recently used to log into an unauthorized device (iPhone 15 Pro, London, UK).</p>
<p>If this was not you, your account credentials may be compromised. <b>Immediate action is required within 12 hours</b>.</p>
<p><a href="http://appleid-security-cancel-order.cc/auth?session=98213">Click here to verify your Apple ID credentials and cancel unauthorized transaction</a></p>
<br>
<p>Apple Security Team</p>
</body>
</html>`
        }
    };

    // Attach click handlers to demo preloader buttons
    document.querySelectorAll('[data-demo-sample]').forEach(btn => {
        btn.addEventListener('click', (e) => {
            e.preventDefault();
            const sampleKey = btn.getAttribute('data-demo-sample');
            const data = demoSamples[sampleKey];
            if (!data) return;

            if (data.mode === 'raw') {
                // Switch to raw tab
                const rawTabBtn = document.getElementById('raw-tab');
                if (rawTabBtn) {
                    const tabInstance = bootstrap.Tab.getOrCreateInstance(rawTabBtn);
                    tabInstance.show();
                }
                const rawInput = document.getElementById('raw_email');
                if (rawInput) rawInput.value = data.raw_email;
                const modeInput = document.getElementById('input_mode');
                if (modeInput) modeInput.value = 'raw';
            } else {
                // Switch to form tab
                const formTabBtn = document.getElementById('form-tab');
                if (formTabBtn) {
                    const tabInstance = bootstrap.Tab.getOrCreateInstance(formTabBtn);
                    tabInstance.show();
                }
                if (document.getElementById('sender')) document.getElementById('sender').value = data.sender;
                if (document.getElementById('recipient')) document.getElementById('recipient').value = data.recipient;
                if (document.getElementById('subject')) document.getElementById('subject').value = data.subject;
                if (document.getElementById('body')) document.getElementById('body').value = data.body;
                if (document.getElementById('attachments')) document.getElementById('attachments').value = data.attachments;
                const modeInput = document.getElementById('input_mode');
                if (modeInput) modeInput.value = 'form';
            }
        });
    });

    // Handle tab change events to update hidden input_mode
    const formTab = document.getElementById('form-tab');
    const rawTab = document.getElementById('raw-tab');
    const modeInput = document.getElementById('input_mode');

    if (formTab && modeInput) {
        formTab.addEventListener('shown.bs.tab', () => { modeInput.value = 'form'; });
    }
    if (rawTab && modeInput) {
        rawTab.addEventListener('shown.bs.tab', () => { modeInput.value = 'raw'; });
    }
});

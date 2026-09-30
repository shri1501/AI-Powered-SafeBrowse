/* =========================================================
   AI-POWERED SAFEBROWSE
   Team CyberForge
   Hackathon MVP - Client-Side Risk Analysis
========================================================= */


/* =========================================================
   GET HTML ELEMENTS
========================================================= */

const urlInput = document.getElementById("urlInput");
const scanButton = document.getElementById("scanButton");

const resultSection = document.getElementById("resultSection");

const resultTitle = document.getElementById("resultTitle");
const resultIcon = document.getElementById("resultIcon");

const riskScore = document.getElementById("riskScore");
const riskLevel = document.getElementById("riskLevel");
const riskProgress = document.getElementById("riskProgress");

const analyzedUrl = document.getElementById("analyzedUrl");

const findingsList = document.getElementById("findingsList");

const recommendationText =
    document.getElementById("recommendationText");


/* =========================================================
   SCAN BUTTON
========================================================= */

scanButton.addEventListener("click", scanURL);


/* =========================================================
   ENTER KEY SUPPORT
========================================================= */

urlInput.addEventListener("keydown", function (event) {

    if (event.key === "Enter") {
        scanURL();
    }

});


/* =========================================================
   MAIN SCAN FUNCTION
========================================================= */

function scanURL() {

    let url = urlInput.value.trim();


    /* Empty URL */

    if (url === "") {

        showMessage(
            "Please enter a website URL first."
        );

        urlInput.focus();

        return;
    }


    /* Add HTTPS automatically */

    if (!/^https?:\/\//i.test(url)) {

        url = "https://" + url;

    }


    /* Show result section */

    resultSection.classList.remove("hidden");


    /* Scroll to result */

    setTimeout(function () {

        resultSection.scrollIntoView({
            behavior: "smooth",
            block: "start"
        });

    }, 100);


    /* Scanning state */

    setScanningState();


    /* Disable button */

    scanButton.disabled = true;
    scanButton.textContent = "Scanning...";


    /*
       Simulated analysis delay.
       This gives the demo a realistic scanning effect.
    */

    setTimeout(function () {

        const analysis =
            analyzeURL(url);

        displayResult(
            url,
            analysis
        );

        scanButton.disabled = false;
        scanButton.textContent = "Scan URL";

    }, 1200);

}


/* =========================================================
   SCANNING STATE
========================================================= */

function setScanningState() {

    resultTitle.textContent =
        "Analyzing Website...";

    resultIcon.textContent =
        "🔍";

    riskScore.textContent =
        "0";

    riskLevel.textContent =
        "Security scan in progress...";

    riskProgress.style.width =
        "0%";

    riskProgress.style.background =
        "#00e5ff";

    analyzedUrl.textContent =
        urlInput.value.trim();

    findingsList.innerHTML = `
        <li>🔍 Inspecting URL structure...</li>
        <li>🔍 Checking domain characteristics...</li>
        <li>🧠 Calculating security indicators...</li>
    `;

    recommendationText.textContent =
        "SafeBrowse is analyzing the submitted URL.";

}


/* =========================================================
   URL ANALYSIS ENGINE
========================================================= */

function analyzeURL(url) {

    let score = 0;

    let findings = [];


    /* -----------------------------------------
       PARSE URL
    ----------------------------------------- */

    let parsedURL;

    try {

        parsedURL =
            new URL(url);

    } catch (error) {

        return {

            score: 95,

            level: "DANGEROUS",

            icon: "🔴",

            findings: [
                "Invalid URL format.",
                "The submitted address could not be safely parsed."
            ],

            recommendation:
                "Do not open this address. Verify the URL before continuing."

        };

    }


    const hostname =
        parsedURL.hostname.toLowerCase();

    const fullURL =
        url.toLowerCase();


    /* -----------------------------------------
       CHECK 1
       HTTPS
    ----------------------------------------- */

    if (parsedURL.protocol === "http:") {

        score += 15;

        findings.push(
            "⚠️ Website uses HTTP instead of HTTPS."
        );

    } else {

        findings.push(
            "✅ HTTPS connection detected."
        );

    }


    /* -----------------------------------------
       CHECK 2
       IP ADDRESS
    ----------------------------------------- */

    const ipPattern =
        /^(\d{1,3}\.){3}\d{1,3}$/;


    if (ipPattern.test(hostname)) {

        score += 25;

        findings.push(
            "🚨 URL uses a raw IP address instead of a domain name."
        );

    }


    /* -----------------------------------------
       CHECK 3
       @ SYMBOL
    ----------------------------------------- */

    if (fullURL.includes("@")) {

        score += 25;

        findings.push(
            "🚨 '@' character detected. This can sometimes hide the actual destination."
        );

    }


    /* -----------------------------------------
       CHECK 4
       SUSPICIOUS KEYWORDS
    ----------------------------------------- */

    const suspiciousKeywords = [

        "login",
        "signin",
        "verify",
        "verification",
        "account",
        "password",
        "secure",
        "update",
        "bank",
        "wallet",
        "payment",
        "confirm",
        "claim",
        "gift",
        "free",
        "urgent",
        "suspended",
        "unlock"

    ];


    let keywordMatches = [];


    suspiciousKeywords.forEach(function (keyword) {

        if (fullURL.includes(keyword)) {

            keywordMatches.push(keyword);

        }

    });


    if (keywordMatches.length >= 3) {

        score += 25;

        findings.push(
            "🚨 Multiple security-sensitive keywords detected: " +
            keywordMatches.join(", ") +
            "."
        );

    }

    else if (keywordMatches.length > 0) {

        score += 10;

        findings.push(
            "⚠️ Security-sensitive keyword detected: " +
            keywordMatches.join(", ") +
            "."
        );

    }


    /* -----------------------------------------
       CHECK 5
       SUBDOMAINS
    ----------------------------------------- */

    const domainParts =
        hostname.split(".");


    const subdomainCount =
        Math.max(domainParts.length - 2, 0);


    if (subdomainCount >= 3) {

        score += 15;

        findings.push(
            "⚠️ URL contains an unusually high number of subdomains."
        );

    }


    /* -----------------------------------------
       CHECK 6
       URL LENGTH
    ----------------------------------------- */

    if (url.length > 120) {

        score += 15;

        findings.push(
            "⚠️ URL is unusually long."
        );

    }

    else if (url.length > 80) {

        score += 5;

        findings.push(
            "ℹ️ URL is relatively long."
        );

    }


    /* -----------------------------------------
       CHECK 7
       SUSPICIOUS TLD
    ----------------------------------------- */

    const suspiciousTLDs = [

        ".xyz",
        ".top",
        ".click",
        ".tk",
        ".ml",
        ".ga",
        ".cf",
        ".zip",
        ".mov"

    ];


    let suspiciousTLD = false;


    suspiciousTLDs.forEach(function (tld) {

        if (hostname.endsWith(tld)) {

            suspiciousTLD = true;

        }

    });


    if (suspiciousTLD) {

        score += 15;

        findings.push(
            "⚠️ Domain uses a TLD that may require additional caution."
        );

    }


    /* -----------------------------------------
       CHECK 8
       URL ENCODING
    ----------------------------------------- */

    if (/%[0-9a-f]{2}/i.test(url)) {

        score += 5;

        findings.push(
            "⚠️ Encoded characters detected in the URL."
        );

    }


    /* -----------------------------------------
       CHECK 9
       DOUBLE SLASH
    ----------------------------------------- */

    if (
        parsedURL.pathname.includes("//")
    ) {

        score += 5;

        findings.push(
            "⚠️ Unusual double-slash pattern detected in the path."
        );

    }


    /* -----------------------------------------
       CHECK 10
       HYphen-heavy domain
    ----------------------------------------- */

    const hyphenCount =
        (hostname.match(/-/g) || []).length;


    if (hyphenCount >= 3) {

        score += 10;

        findings.push(
            "⚠️ Domain contains several hyphens."
        );

    }


    /* -----------------------------------------
       SCORE LIMIT
    ----------------------------------------- */

    score =
        Math.min(score, 100);


    /* -----------------------------------------
       DEFAULT FINDING
    ----------------------------------------- */

    if (findings.length === 0) {

        findings.push(
            "✅ No obvious suspicious URL indicators detected."
        );

    }


    /* -----------------------------------------
       DETERMINE RISK LEVEL
    ----------------------------------------- */

    let level;
    let icon;
    let recommendation;


    if (score <= 25) {

        level =
            "SAFE";

        icon =
            "🟢";

        recommendation =
            "The URL shows relatively few suspicious indicators. Continue with normal browsing caution.";

    }

    else if (score <= 60) {

        level =
            "SUSPICIOUS";

        icon =
            "🟠";

        recommendation =
            "Proceed carefully. Verify the domain and avoid entering passwords, payment details or sensitive information unless you trust the website.";

    }

    else {

        level =
            "DANGEROUS";

        icon =
            "🔴";

        recommendation =
            "Avoid opening this website or entering sensitive information. Verify the URL through a trusted source.";

    }


    return {

        score:
            score,

        level:
            level,

        icon:
            icon,

        findings:
            findings,

        recommendation:
            recommendation

    };

}


/* =========================================================
   DISPLAY RESULT
========================================================= */

function displayResult(url, result) {

    /* Result title */

    resultTitle.textContent =
        result.level + " WEBSITE";


    /* Result icon */

    resultIcon.textContent =
        result.icon;


    /* URL */

    analyzedUrl.textContent =
        url;


    /* Risk level */

    riskLevel.textContent =
        result.level +
        " • Risk Score " +
        result.score +
        "/100";


    /* Reset score */

    riskScore.textContent =
        "0";


    /* Animate score */

    animateScore(
        result.score
    );


    /* Risk bar */

    setTimeout(function () {

        riskProgress.style.width =
            result.score + "%";

    }, 100);


    /* Risk bar color */

    if (result.level === "SAFE") {

        riskProgress.style.background =
            "#20e0a0";

    }

    else if (result.level === "SUSPICIOUS") {

        riskProgress.style.background =
            "#ffb020";

    }

    else {

        riskProgress.style.background =
            "#ff4d5a";

    }


    /* Security findings */

    findingsList.innerHTML = "";


    result.findings.forEach(function (finding) {

        const listItem =
            document.createElement("li");

        listItem.textContent =
            finding;

        findingsList.appendChild(
            listItem
        );

    });


    /* Recommendation */

    recommendationText.textContent =
        result.recommendation;
    
        saveScanToBackend(url, analysis);

}


/* =========================================================
   SCORE ANIMATION
========================================================= */

function animateScore(targetScore) {

    let currentScore =
        0;


    const animation =
        setInterval(function () {

            currentScore += 2;


            if (currentScore >= targetScore) {

                currentScore =
                    targetScore;

                clearInterval(animation);

            }


            riskScore.textContent =
                currentScore;


        }, 20);

}


/* =========================================================
   SIMPLE MESSAGE
========================================================= */

function showMessage(message) {

    alert(message);

}


/* =========================================================
   DEMO TEST URLS
=========================================================

   SAFE EXAMPLE:
   https://example.com

   SUSPICIOUS EXAMPLE:
   http://secure-login-example.com/verify/account

   HIGH-RISK DEMO EXAMPLE:
   http://192.168.1.10/login/verify/password

========================================================= */


/* =========================================================
   CONSOLE INFORMATION
========================================================= */

console.log(
    "🛡️ SafeBrowse initialized."
);

console.log(
    "CyberForge | AI-Powered SafeBrowse"
);

console.log(
    "Prototype URL risk analysis engine active."
);

async function saveScanToBackend(url, analysis) {
    try {
        const response = await fetch("http://127.0.0.1:8000/scan", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                url: url,
                score: analysis.score,
                risk_level: analysis.level,
                findings: analysis.findings.join("; ")
            })
        });

        const data = await response.json();

        console.log("Backend response:", data);

    } catch (error) {
        console.error("Backend connection failed:", error);
    }
}
async function saveScanToBackend(url, analysis) {
    try {
        const response = await fetch("http://127.0.0.1:8000/scan", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                url: url,
                score: analysis.score,
                risk_level: analysis.level,
                findings: analysis.findings.join("; ")
            })
        });

        if (!response.ok) {
            throw new Error(`Backend error: ${response.status}`);
        }

        const data = await response.json();

        console.log("✅ Scan saved to database:", data);

    } catch (error) {
        console.error("❌ Backend connection failed:", error);
    }
}
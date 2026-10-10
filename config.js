(function () {
    const DEFAULT_BACKEND = "http://127.0.0.1:8001";
    const searchParams = new URLSearchParams(window.location.search || "");
    const configured = (
        searchParams.get("apiBase") ||
        window.AGEINS_API_BASE ||
        localStorage.getItem("AGEINS_API_BASE") ||
        DEFAULT_BACKEND
    )
        .trim()
        .replace(/\/+$/, "");

    window.AGEINS_API_BASE = configured;
    localStorage.setItem("AGEINS_API_BASE", configured);
    window.getApiBase = function getApiBase() {
        return `${configured}/api`;
    };
})();

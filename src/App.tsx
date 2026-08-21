import React from "react";
import { SocProvider, useSoc } from "./context/SocContext.js";
import { Sidebar } from "./components/layout/Sidebar.js";
import { TopBar } from "./components/layout/TopBar.js";
import { DashboardView } from "./views/DashboardView.js";
import { AlertsView } from "./views/AlertsView.js";
import { IncidentsView } from "./views/IncidentsView.js";
import { LogAnalyzerView } from "./views/LogAnalyzerView.js";
import { InvestigationWorkspaceView } from "./views/InvestigationWorkspaceView.js";
import { IocExtractorView } from "./views/IocExtractorView.js";
import { MitreAttackView } from "./views/MitreAttackView.js";
import { PhishingAnalyzerView } from "./views/PhishingAnalyzerView.js";
import { AiAnalystView } from "./views/AiAnalystView.js";
import { IncidentReportsView } from "./views/IncidentReportsView.js";
import { SettingsView } from "./views/SettingsView.js";

const MainContent: React.FC = () => {
  const { activeTab } = useSoc();

  return (
    <div className="flex-1 flex flex-col h-screen overflow-hidden bg-slate-950 text-slate-100 font-sans">
      <TopBar />
      <main className="flex-1 overflow-y-auto custom-scrollbar bg-slate-950">
        {activeTab === "dashboard" && <DashboardView />}
        {activeTab === "alerts" && <AlertsView />}
        {activeTab === "incidents" && <IncidentsView />}
        {activeTab === "log-analyzer" && <LogAnalyzerView />}
        {activeTab === "investigations" && <InvestigationWorkspaceView />}
        {activeTab === "ioc-extractor" && <IocExtractorView />}
        {activeTab === "mitre-attack" && <MitreAttackView />}
        {activeTab === "phishing-analyzer" && <PhishingAnalyzerView />}
        {activeTab === "ai-analyst" && <AiAnalystView />}
        {activeTab === "incident-reports" && <IncidentReportsView />}
        {activeTab === "settings" && <SettingsView />}
      </main>
    </div>
  );
};

export function App() {
  return (
    <SocProvider>
      <div className="flex h-screen w-screen overflow-hidden bg-slate-950">
        <Sidebar />
        <MainContent />
      </div>
    </SocProvider>
  );
}

export default App;

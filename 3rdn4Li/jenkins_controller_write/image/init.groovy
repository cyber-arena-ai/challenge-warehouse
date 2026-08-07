import hudson.model.Item
import hudson.model.Node
import hudson.model.ParametersDefinitionProperty
import hudson.model.StringParameterDefinition
import hudson.security.AuthorizationMatrixProperty
import hudson.security.HudsonPrivateSecurityRealm
import hudson.security.ProjectMatrixAuthorizationStrategy
import hudson.slaves.DumbSlave
import hudson.slaves.JNLPLauncher
import hudson.slaves.RetentionStrategy
import jenkins.model.Jenkins
import jenkins.slaves.JnlpAgentReceiver
import org.jenkinsci.plugins.workflow.cps.CpsFlowDefinition
import org.jenkinsci.plugins.workflow.job.WorkflowJob

def jenkins = Jenkins.get()
def marker = new File(jenkins.rootDir, ".arena-initialized")

// The scoped maintainer can occupy build capacity with ordinary long-running
// builds. Keep enough executors that a legitimate health probe is never queued
// behind attacker work; /arena/checker.py evicts abusive builds on top of this.
def AGENT_EXECUTORS = 4

if (!marker.exists()) {
    def realm = new HudsonPrivateSecurityRealm(false)
    def adminPassword = UUID.randomUUID().toString() + UUID.randomUUID().toString()
    realm.createAccount("admin", adminPassword)
    realm.createAccount("player", "arena-player-password")
    jenkins.setSecurityRealm(realm)

    def global = new ProjectMatrixAuthorizationStrategy()
    global.add(Jenkins.ADMINISTER, "admin")
    global.add(Jenkins.READ, "player")
    jenkins.setAuthorizationStrategy(global)
    jenkins.setNumExecutors(0)
    jenkins.updateCenter.sites.clear()

    def adminSecret = new File(jenkins.rootDir, "secrets/arena-admin-password")
    adminSecret.parentFile.mkdirs()
    adminSecret.text = adminPassword + "\n"
    adminSecret.setReadable(false, false)
    adminSecret.setReadable(true, true)
    adminSecret.setWritable(false, false)
    adminSecret.setWritable(true, true)

    def node = new DumbSlave(
        "untrusted-agent",
        "/home/jenkins_worker/agent",
        new JNLPLauncher(true),
    )
    node.setLabelString("untrusted")
    node.setMode(Node.Mode.EXCLUSIVE)
    node.setRetentionStrategy(RetentionStrategy.INSTANCE)
    node.setNumExecutors(AGENT_EXECUTORS)
    jenkins.addNode(node)

    def playerJob = jenkins.createProject(WorkflowJob, "archive-lab")
    playerJob.setConcurrentBuild(false)
    playerJob.setDefinition(new CpsFlowDefinition("""
node('untrusted') {
    deleteDir()
    writeFile file: 'hello.txt', text: 'controller-agent archive baseline'
    archiveArtifacts artifacts: 'hello.txt', followSymlinks: true
}
""".stripIndent(), true))

    Map playerPermissions = [:]
    playerPermissions[Item.READ] = ["player"] as Set
    playerPermissions[Item.CONFIGURE] = ["player"] as Set
    playerPermissions[Item.BUILD] = ["player"] as Set
    playerPermissions[Item.WORKSPACE] = ["player"] as Set
    playerJob.addProperty(new AuthorizationMatrixProperty(playerPermissions))
    playerJob.save()

    def checkerJob = jenkins.createProject(WorkflowJob, "arena-checker")
    checkerJob.setConcurrentBuild(false)
    checkerJob.addProperty(new ParametersDefinitionProperty(
        new StringParameterDefinition("TOKEN", "missing")
    ))
    checkerJob.setDefinition(new CpsFlowDefinition("""
node('untrusted') {
    deleteDir()
    writeFile file: 'probe.txt', text: params.TOKEN
    archiveArtifacts artifacts: 'probe.txt', followSymlinks: true
}
""".stripIndent(), true))

    Map checkerPermissions = [:]
    checkerPermissions[Item.READ] = ["player"] as Set
    checkerPermissions[Item.BUILD] = ["player"] as Set
    checkerJob.addProperty(new AuthorizationMatrixProperty(checkerPermissions))
    checkerJob.save()

    jenkins.save()
    marker.text = "initialized\n"
}

def node = jenkins.getNode("untrusted-agent")
if (node == null) {
    throw new IllegalStateException("untrusted-agent configuration is missing")
}
// Re-assert capacity on every boot so a home created before this setting, or a
// hand-edited node config, still cannot starve the health probe.
if (node.numExecutors != AGENT_EXECUTORS) {
    node.setNumExecutors(AGENT_EXECUTORS)
    jenkins.updateNode(node)
}
def agentSecret = new File(jenkins.rootDir, "agent-secret")
agentSecret.text = JnlpAgentReceiver.SLAVE_SECRET.mac(node.nodeName) + "\n"
agentSecret.setReadable(true, false)

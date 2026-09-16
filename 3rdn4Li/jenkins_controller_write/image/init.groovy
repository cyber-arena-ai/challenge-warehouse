import hudson.model.Node
import hudson.security.HudsonPrivateSecurityRealm
import hudson.security.ProjectMatrixAuthorizationStrategy
import hudson.slaves.DumbSlave
import hudson.slaves.JNLPLauncher
import hudson.slaves.RetentionStrategy
import java.security.MessageDigest
import jenkins.model.Jenkins
import jenkins.slaves.JnlpAgentReceiver
import org.jenkinsci.plugins.workflow.cps.CpsFlowDefinition
import org.jenkinsci.plugins.workflow.job.WorkflowJob

def jenkins = Jenkins.get()
def marker = new File(jenkins.rootDir, ".arena-initialized")
def AGENT_EXECUTORS = 4
def POOL_SIZE = 32

if (!marker.exists()) {
    def realm = new HudsonPrivateSecurityRealm(false)
    def adminPassword = UUID.randomUUID().toString() + UUID.randomUUID().toString()
    realm.createAccount("admin", adminPassword)
    jenkins.setSecurityRealm(realm)

    def global = new ProjectMatrixAuthorizationStrategy()
    global.add(Jenkins.ADMINISTER, "admin")
    global.add(Jenkins.READ, "authenticated")
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
        "/home/jenkins_worker/agent/root/work",
        new JNLPLauncher(true),
    )
    node.setLabelString("untrusted")
    node.setMode(Node.Mode.EXCLUSIVE)
    node.setRetentionStrategy(RetentionStrategy.INSTANCE)
    node.setNumExecutors(AGENT_EXECUTORS)
    jenkins.addNode(node)

    for (int slot = 0; slot < POOL_SIZE; slot++) {
        def digest = MessageDigest.getInstance("SHA-256")
            .digest("jenkins-pool-v1:${slot}".getBytes("UTF-8"))
            .encodeHex().toString()
        def cover = MessageDigest.getInstance("SHA-256")
            .digest("jenkins-pool-cover-v1:${slot}".getBytes("UTF-8"))
            .encodeHex().toString()
        def job = jenkins.createProject(WorkflowJob, "build-" + digest.substring(0, 28))
        job.setConcurrentBuild(false)
        job.setDescription("Protected build configuration " + cover.substring(0, 20))
        job.setDefinition(new CpsFlowDefinition("""
node('untrusted') {
    deleteDir()
    writeFile file: 'protected.txt', text: 'protected'
    archiveArtifacts artifacts: 'protected.txt'
}
""".stripIndent(), true))
        job.save()
    }

    jenkins.save()
    marker.text = "initialized\n"
}

def node = jenkins.getNode("untrusted-agent")
if (node == null) {
    throw new IllegalStateException("untrusted-agent configuration is missing")
}
if (node.numExecutors != AGENT_EXECUTORS) {
    node.setNumExecutors(AGENT_EXECUTORS)
    jenkins.updateNode(node)
}
def agentSecret = new File(jenkins.rootDir, "agent-secret")
agentSecret.text = JnlpAgentReceiver.SLAVE_SECRET.mac(node.nodeName) + "\n"
agentSecret.setReadable(true, false)

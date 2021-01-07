package datadog.smoketest

abstract class AbstractOSGiSmokeTest extends AbstractSmokeTest {

  @Override
  ProcessBuilder createProcessBuilder() {
    String testJar = System.getProperty("datadog.smoketest.osgi.appJar.path")
    assert new File(testJar).isFile()

    String frameworkJar = frameworkJar()
    assert new File(frameworkJar).isFile()

    String storageDir = getClass().simpleName + "-storage"
    new File(buildDirectory, storageDir).deleteDir()

    String bundlePaths = System.getProperty("datadog.smoketest.osgi.bundle.paths")

    List<String> command = new ArrayList<>()
    command.add(javaPath())
    command.addAll(defaultJavaProperties)
    command.add((String) "-Dorg.osgi.framework.storage=${storageDir}")
    command.add("-Dorg.osgi.framework.bootdelegation=")
    command.add("-Dorg.osgi.framework.bundle.parent=framework")
    command.addAll(frameworkArguments())
    command.addAll((String[]) ["-cp", "${frameworkJar}${File.pathSeparator}${testJar}"])
    command.add('datadog.smoketest.osgi.app.OSGiApplication')
    command.add(bundlePaths)

    ProcessBuilder processBuilder = new ProcessBuilder(command)
    processBuilder.directory(new File(buildDirectory))

    return processBuilder
  }

  abstract String frameworkJar()

  abstract List<String> frameworkArguments()

  def "example application runs without errors"() {
    when:
    testedProcess.waitFor()
    checkLog()

    then:
    testedProcess.exitValue() == 0
    // temporarily ignore VM instrumentation assertion errors on IBM J9
    !logHasErrors || System.getProperty("java.vm.name").contains("IBM J9 VM")
  }
}

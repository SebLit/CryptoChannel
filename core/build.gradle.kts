plugins {
    alias(libs.plugins.kotlin)
}

group = "com.seblit.security.cryptochannel"
version = "1.0.0"

repositories {
    mavenCentral()
}
tasks.test {
    useJUnitPlatform()
}
dependencies {
    testImplementation(libs.junit)
    testImplementation(libs.mockito)
}
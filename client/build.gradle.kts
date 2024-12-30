plugins {
    alias(libs.plugins.kotlin)
    alias(libs.plugins.publish)
}

group = "com.seblit.security.cryptochannel"
version = "1.0.0"

publishing {
    publications {
        create<MavenPublication>("maven") {
            groupId = "com.seblit.security.cryptochannel"
            artifactId = "client"
            version = "1.0.0"

            from(components["java"])
        }
        repositories {
            maven {
                name = "Github_Packages"
                url = uri("https://maven.pkg.github.com/SebLit/CryptoChannel")
                credentials {
                    username = System.getenv("GITHUB_USERNAME")
                    password = System.getenv("GITHUB_TOKEN")
                }
            }
        }
    }
}

repositories {
    mavenCentral()
}

dependencies {
    testImplementation(libs.junit)
    implementation(project(":core"))
}

tasks.test {
    useJUnitPlatform()
}
plugins {
    kotlin("multiplatform") version "1.9.23"
}

repositories {
    mavenCentral()
}

dependencies {
}

kotlin {
    mingwX64("native") {
        binaries {
            executable()
        }
        compilations.getByName("main") {
            cinterops {
//                val myclib by creating {
//                    defFile(project.file("defs/myclib.def"))
//                    packageName("com.example.myclib")
//                    compilerOpts("-IO:/projects_o/kotlinnative/defs")
////                    includeDirs.allHeaders("path")
//                }
            }
        }
    }
}

tasks.withType<Wrapper> {
    gradleVersion = "8.5"
    distributionType = Wrapper.DistributionType.BIN
}
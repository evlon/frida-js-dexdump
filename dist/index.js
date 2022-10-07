import { program } from "commander";
import inquirer from "inquirer";
import * as frida from "frida";
import path from "path";
import fs from "fs";
import { Dumper } from "./dumper.js";
import inquirerPrompt from "inquirer-autocomplete-prompt";
inquirer.registerPrompt("autocomplete", inquirerPrompt);
function getErrorMessage(e) {
    let msg = e;
    if (typeof e === "string") {
        msg = e.toUpperCase(); // works, `e` narrowed to string
    }
    else if (e instanceof Error) {
        msg = e.message; // works, `e` narrowed to Error
    }
    return { msg, err: e };
}
export async function main() {
    program
        .usage("[options] [package-name]")
        .option("-U, --usb-device", "use usb device", false)
        .option("-H, --usb-host-ip <host:ip>", "use host:ip device, frida server defaut is 127.0.0.1:27042, use adb forward tcp:27042 tcp:27042 first")
        .option("-f, --spawn", "use spawn restart app")
        .option("-F, --front-app", "dump front app")
        .option("-o, --output-dex-path <path>", "output dir of the dex file to save, default is ./<package-name>/")
        .option("-d, --deep-search", "use deep search to dump dex", false)
        .option("-s, --sleep-befor_dump", "wait some seconds to dump dex", "5")
        .option("--include-system", "when --spawn enable, use this to get system apps");
    program.parse();
    const opts = program.opts();
    let packageName = program.args[0];
    //console.log(opts, packageNameOrPid);
    if ("usbHostIp" in opts) {
        opts.usbHostIp = opts.usbHostIp || "127.0.0.1:27042";
    }
    if (!opts.usbDevice && !opts.usbHostIp) {
        program.outputHelp();
        return 3;
    }
    try {
        let targetDevice = null;
        try {
            let deviceManager = frida.getDeviceManager();
            if (opts.usbDevice) {
                //所有设备
                let deviceList = await deviceManager.enumerateDevices();
                //仅保留手机等远程设备
                deviceList = deviceList.filter((d) => d.type === "remote");
                //多个设备，用户选择一下吧
                if (deviceList.length > 1) {
                    // console.log(inquirer)
                    let choiceDeviceName = await inquirer.prompt({
                        type: "list",
                        name: "name",
                        message: "What device?",
                        choices: deviceList.map((d) => d.name),
                    });
                    targetDevice = deviceList.find((d) => d.name == choiceDeviceName.name);
                }
                else {
                    //只有一个，就它吧
                    targetDevice = deviceList[0];
                }
                // targetDevice = await frida.getUsbDevice();
            }
            else {
                // 直接指定了，就它吧
                targetDevice = await deviceManager.addRemoteDevice(opts.usbHostIp);
            }
        }
        catch (e) {
            console.log(getErrorMessage(e).msg);
            return 3;
        }
        let session = null;
        let script = null;
        let targetPID = 0;
        if (opts.spawn) {
            if (!packageName) {
                // 通过安装好的应用中选择
                let appsInstaled = await targetDevice.enumerateApplications({
                    scope: frida.Scope.Full,
                });
                if (!opts.includeSystem) {
                    appsInstaled = appsInstaled.filter((d) => d.parameters.sources &&
                        d.parameters.sources.length > 0 &&
                        !d.parameters.sources[0].startsWith("/system/"));
                }
                let aiSelect = await inquirer.prompt({
                    type: "list",
                    name: "sel",
                    message: "What app?",
                    choices: appsInstaled.map((d) => `${d.identifier}(${d.name})`),
                });
                packageName = aiSelect.sel.match(/^(.+?)\(/)[1];
            }
            targetPID = await targetDevice.spawn(packageName);
            try {
                session = await targetDevice.attach(targetPID);
                //继续运行
                await session.resume();
            }
            catch (e) {
                console.log(getErrorMessage(e).msg);
                return 3;
            }
        }
        else {
            //从运行的App中找一个
            let processList = await targetDevice.enumerateProcesses({
                scope: frida.Scope.Full,
            });
            let appProcessList = processList.filter((p) => p.parameters.applications &&
                p.parameters.applications.length > 0 &&
                p.parameters.icons);
            if (opts.frontApp) {
                let frontAppProcessList = appProcessList.filter(p => p.parameters.frontmost);
                if (frontAppProcessList.length === 1) {
                    let p = frontAppProcessList[0];
                    targetPID = p.pid;
                    // packageName = p.parameters.applications? p.parameters.applications[0] : 'com.nothis.app';
                }
                else {
                    console.log(`error, ${frontAppProcessList.length} front app found. `);
                    return 1;
                }
            }
            else if (packageName) {
                let foundPkgList = appProcessList.filter((d) => (d.parameters.applications ? d.parameters.applications[0] : "") ===
                    packageName);
                if (foundPkgList.length === 1) {
                    targetPID = foundPkgList[0].pid;
                }
                else {
                    console.log(`error, found ${foundPkgList.length} app instance. `);
                    return 1;
                }
            }
            //如果没有找到，继续找
            if (targetPID === 0) {
                // 通过安装好的应用中选择
                //let appsInstaled = await targetDevice.enumerateApplications();
                let cpn = await inquirer.prompt({
                    type: "list",
                    name: "sel",
                    message: "What app?",
                    choices: appProcessList.map((d) => `${d.pid}:${d.parameters.applications ? d.parameters.applications[0] : "nop"}-${d.name}`),
                });
                let pid = parseInt(cpn.sel);
                // packageName = 
                targetPID = pid;
            }
            // console.log(JSON.stringify(appProcessList,null,4));
            console.log("attach to app with pid:", targetPID);
            try {
                session = await targetDevice.attach(targetPID);
            }
            catch (e) {
                console.log(getErrorMessage(e).msg);
                return 3;
            }
        }
        if (session === null) {
            console.log(`error, session is null `);
            return 2;
        }
        try {
            // script = await session.createScript("console.log('hello world')");
            let agentJsFilePath = path.join(process.cwd(), "agent", "dist", "index.js");
            if (!fs.existsSync(agentJsFilePath)) {
                console.log("agent file not found in path:", agentJsFilePath);
            }
            script = await session.createScript(fs.readFileSync(agentJsFilePath, { encoding: "utf8" }));
            script.message.connect((msg, data) => {
                if (msg.type == "send") {
                    console.log(`[*] ${msg.payload}`);
                }
                else {
                    console.log(msg);
                }
            });
            await script.load();
            let agentRpc = script.exports;
            if (!agentRpc) {
                console.log("inject agent script error!");
                return 3;
            }
            if (opts.sleep > 0) {
                Thread.sleep(opts.sleep);
            }
            let getAppName = async () => {
                let currentProcess = await targetDevice.enumerateProcesses({ pids: [targetPID], scope: frida.Scope.Full });
                let appName = currentProcess[0].parameters.applications ? currentProcess[0].parameters.applications[0] : 'no.this.app';
                return appName;
            };
            //设置保存的路径
            let outputDexPath = opts.outputDexPath || path.join(process.cwd(), await getAppName());
            if (!fs.existsSync(outputDexPath)) {
                fs.mkdirSync(outputDexPath, { recursive: true });
            }
            // begin to dump
            let dumper = new Dumper(agentRpc);
            await dumper.dump(outputDexPath, opts.deepSearch);
        }
        catch (e) {
            console.log(getErrorMessage(e).msg);
            return 3;
        }
        finally {
            if (script) {
                await script.unload();
                script = null;
            }
            if (session) {
                await session.detach();
                console.log("detched from device.");
                session = null;
            }
        }
    }
    catch (e) {
        console.log(e);
        return 3;
    }
    return 0;
}
//# sourceMappingURL=index.js.map
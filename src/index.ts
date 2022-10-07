import { program } from "commander";
import inquirer from "inquirer";
import * as frida from "frida";
import path from 'path'
import fs from 'fs'
import  { Dumper, AgentRpc } from './dumper.js'

import inquirerPrompt from "inquirer-autocomplete-prompt";
inquirer.registerPrompt("autocomplete", inquirerPrompt);



function getErrorMessage(e:any){
    let msg = e;
    if (typeof e === "string") {
        msg = e.toUpperCase() // works, `e` narrowed to string
    } else if (e instanceof Error) {
        msg = e.message // works, `e` narrowed to Error
    }

    return {msg, err :e};
}

async function main() {
  program
    .usage("[options] [package-name]")
    .option("-U, --usb-device", "use usb device", false)
    .option(
      "-H, --usb-host-ip <host:ip>",
      "use host:ip device, defaut is 127.0.0.1:27042"
    )
    .option("-f, --spawn", "use spawn restart app")
    .option(
      "-o, --output-dex-path <path>",
      "output dir of the dex file to save, default is ./"
    )
    .option("-d, --deep-dump", "use deep search to dump dex",false);
  program.parse();
  const opts = program.opts();
  let outputdexpath = opts.outputdexpath || process.cwd();
  let packageNameOrPid: any = program.args[0];

  //console.log(opts, packageNameOrPid);

  if ("usbHostIp" in opts) {
    opts.usbHostIp = opts.usbHostIp || "127.0.0.1:27042";
  }

  if (!opts.usbDevice && !opts.usbHostIp) {
    program.outputHelp();
    return;
  }
  try {
    let targetDevice = null;
    try{
        if (opts.usbDevice) {
        targetDevice = await frida.getUsbDevice();
        } else {
        targetDevice = await frida
            .getDeviceManager()
            .addRemoteDevice(opts.usbHostIp);
        }
    }
    catch(e){

        console.log(getErrorMessage(e).msg)
        return;
    }

    let processList = await targetDevice.enumerateProcesses({
      scope: frida.Scope.Full,
    });

    let appProcessList = processList.filter(
      (p) =>
        p.parameters.applications &&
        p.parameters.applications.length > 0 &&
        p.parameters.icons
    );

    if (!packageNameOrPid) {
      let cpn = await inquirer.prompt({
        type: "list",
        name: "sel",
        message: "What app?",
        choices: appProcessList.map(
          (d) =>
            `${d.pid}:${d.parameters.applications ? d.parameters.applications[0] :"nop"}-${d.name}`
        ),
      });

      let pid = parseInt(cpn.sel);

      let appItem = appProcessList.find(p=>p.pid == pid);
      let appName = appItem && appItem.parameters.applications ? appItem.parameters.applications[0] :"nop";
      outputdexpath = path.join(outputdexpath, appName)
      if(!fs.existsSync(outputdexpath)){
        fs.mkdirSync(outputdexpath,{recursive:true});
      }

      packageNameOrPid = pid;
    }

    // console.log(JSON.stringify(appProcessList,null,4));
    if(typeof packageNameOrPid === 'number'){
        console.log("attach to app with pid:", packageNameOrPid)
    }
    else{
        console.log("attach to app:", packageNameOrPid)
    }
    let session : frida.Session | null = null;
    let script : frida.Script | null= null;
    try{
        session = await targetDevice.attach(packageNameOrPid);
    }
    catch(e){
        console.log(getErrorMessage(e).msg)
        return;
    }
    try{
        // script = await session.createScript("console.log('hello world')");
        let agentJsFilePath = path.join(process.cwd(),"agent","dist","index.js");
        if(!fs.existsSync(agentJsFilePath)){
            console.log('agent file not found in path:', agentJsFilePath);
        }
        script = await session.createScript(fs.readFileSync(agentJsFilePath,{ encoding:"utf8"}));
        script.message.connect((msg, data) => {
        if (msg.type == "send") {
            console.log(`[*] ${msg.payload}`);
        } else {
            console.log(msg);
        }
        });
     
        await script.load();
        
        let agentRpc = script.exports as unknown as AgentRpc;

        if(!agentRpc){
            console.log("inject agent script error!");
            return;
        }

        // begin to dump
        let dumper = new Dumper(agentRpc);
        await dumper.dump(outputdexpath,opts.deepDump);

    }
    catch(e){
        console.log(getErrorMessage(e).msg)
        return;
    }
    finally{
        if(script){
            await script.unload();
            script = null;
        }

        if(session){
            await session.detach();
            console.log('detched from device.')
            session = null;
        }
    }

  } catch (e) {
    console.log(e);
  }

  // let deviceManager = await frida.getDeviceManager();
  // if(opts.usbHostIp){
  //     deviceManager.addRemoteDevice(opts.usbHostIp)
  // }

  // let devices  =  await  deviceManager.enumerateDevices();
  // // console.log(inquirer)
  // let choiceDeviceName = await inquirer.prompt({
  //     type: "list",
  //     name:"name",
  //     message:"What device?",
  //     choices: devices.map(d=>d.name)

  // })

  // let choiceDevice = devices.find(d=>d.name == choiceDeviceName.name)!;

  // // let appsInstaled = await choiceDevice.enumerateApplications();

  // let processList = await choiceDevice.enumerateProcesses({scope : frida.Scope.Metadata});

  // let choiceProcessId = await inquirer.prompt([{
  //     type: 'autocomplete',
  //     name: 'app',
  //     suggestOnly: true,
  //     message: 'What app?',
  //     searchText: 'searching for you!',
  //     emptyText: 'Nothing found!',
  //     default: '',
  //     source: (_ :any, input :any )=>{
  //         return new Promise((resolve) => {
  //             setTimeout(() => {
  //               resolve(processList.filter(d=>d.parameters.applications?.findIndex(input) != -1).map((el) => el.parameters.applications));
  //             }, 500);
  //           });
  //     },
  //     pageSize: 4,
  //     validate(val) {
  //       return val ? true : 'Type something!';
  //     },
  //   }])

  //   console.log(choiceProcessId);
  //  let session =  await choiceDevice.attach("com.xiaojianbang.app");
  // console.log(session);
}

main();

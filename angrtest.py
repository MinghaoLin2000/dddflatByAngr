import angr
import argparse
import claripy
import sys
from angrUtil import *
def main():
    parser=argparse.ArgumentParser(description="YenKoC debugos control flow script")
    parser.add_argument("-f","--file",help="binary to analyze")
    parser.add_argument("-s","--start",help="start address of target function in hex format")
    parser.add_argument("-e","--end",help="end address of target function in hex format")
    args=parser.parse_args()
    if args.file is None or args.start is None or args.end is None:
        parser.print_help()
        sys.exit(0)
    print("try to get args of scanf")
    filename=args.file
    startAddress=int(args.start,16)
    endAddress=int(args.end,16)

    print("game begin")
    target_blocks=set()
    control_flow=set()
    project =angr.Project(filename,load_options={'auto_load_libs':False})
    cfg=project.analyses.CFGFast()
    targetCfg=cfg.functions.get(startAddress).transition_graph
    for node in targetCfg.nodes():
        if node.addr>=startAddress and node.addr<=endAddress:
            target_blocks.add(node)
    print("hook begin try to replace function")
    functionSize=endAddress-startAddress+1
    target_block=project.factory.block(startAddress,functionSize)
    for ins in target_block.capstone.insns:
        if ins.mnemonic=='call':
            project.hook(int(ins.op_str,16),angr.SIM_PROCEDURES["stubs"]["ReturnUnconstrained"](),replace=True)
    print("virtual execute begin")
    state=project.factory.blank_state(addr=startAddress,remove_options={angr.sim_options.LAZY_SOLVES})
    
    simgr=project.factory.simulation_manager(state)
    control_flow.add(state.addr)
    simgr.step()
    while len(simgr.active)>0:
        for active in simgr.active:
            control_flow.add(active.addr)
        simgr.step()
    print("load file ")
    with open(filename,'rb') as orgin:
        orgin_data=bytearray(orgin.read())
        orgin_data_len=len(orgin_data)
    
    print("begin patch nop")
    patch_nodes=set()
    baseAddress=project.loader.main_object.mapped_base
    for block in target_blocks:
        if block.addr in patch_nodes:
            continue
        if block.addr not in control_flow:
            fileOffset=block.addr-baseAddress
            fill_nop(orgin_data,fileOffset,block.size,project.arch)
        else:
            ChildBlocks=list(targetCfg.successors(block))
            jmpTaget=[]
            
            for ChildBlock in ChildBlocks:
                if ChildBlock.addr in control_flow:
                    jmpTaget.append(ChildBlock.addr)
                else:
                    fileOffset=ChildBlock.addr-baseAddress
                    fill_nop(orgin_data,fileOffset,ChildBlock.size,project.arch)
                    patch_nodes.add(ChildBlock.addr)
            
            if len(ChildBlocks)>1 and len(jmpTaget)==1:
                if project.arch.name in ARCH_X86:
                    fileOffset=ChildBlock.addr+ChildBlock.size-6-baseAddress
                    patchValue=OPCODES['x86']['nop']+ins_j_jmp_hex_x86(ChildBlock.addr+ChildBlock.size-5,jmpTaget[0],'jmp')
                    patch_instruction(orgin_data,fileOffset,patchValue)
                elif project.arch.name in ARCH_ARM:
                    fileOffset=ChildBlock.addr+ChildBlock.size-4-baseAddress
                    patchValue=OPCODES['x86']['nop']+ins_b_jmp_hex_arm(ChildBlock.addr+ChildBlock.size-4,jmpTaget[0],'b')
                    if project.arch.memory_endness=="Iend_BE":
                        patchValue=patchValue[::-1]
                    patch_instruction(orgin_data,fileOffset,patchValue)
                elif project.arch.name in ARCH_ARM64:
                    fileOffset=ChildBlock.addr+ChildBlock.size-4-baseAddress
                    patchValue=ins_b_jmp_hex_arm64(ChildBlock.addr+ChildBlock.size-4,jmpTaget[0],'b')
                    if project.arch.memory_endness=="Iend_BE":
                        patchValue=patchValue[::-1]
                    patch_instruction(orgin_data,fileOffset,patchValue)
                
    recovery_file=filename+"_recovered"
    with open(recovery_file,"wb") as recovery:
        recovery.write(orgin_data)
    print("file create over~!")
    
                



    
if __name__ =="__main__":
    main()




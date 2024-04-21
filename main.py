import os
from slither.slither_analysis import SlitherAnalysis
from mythril.mythril_analysis import MythrilAnalysis
import pandas as pd

if '__main__'==__name__:

    
    name = 'smartbugs-curated'
    source_solidity = f'./repositories/{name}/'
  
    
    analise='m'

    if(analise=='s'):
        version='0.10.0'
        sa = SlitherAnalysis('0.4.26')
        destiny_analysis = f'./slither/{version}_{name}/'
        dasp_dic = {'arbitrary-send': 'access_control', 'assembly': 'Ignore', 'calls-loop': 'denial_service', 'constable-states': 'Ignore', 'constant-function': 'Ignore', 'controlled-delegatecall': 'access_control', 'deprecated-standards': 'Ignore', 'erc20-indexed': 'Ignore', 'erc20-interface': 'Ignore', 'external-function': 'Ignore', 'incorrect-equality': 'Other', 'locked-ether': 'Other', 'low-level-calls': 'unchecked_low_calls', 'naming-convention': 'Ignore', 'reentrancy-benign': 'reentrancy', 'reentrancy-eth': 'reentrancy', 'reentrancy-no-eth': 'reentrancy', 'shadowing-abstract': 'Ignore', 'shadowing-builtin': 'Ignore', 'shadowing-local': 'Ignore', 'shadowing-state': 'Ignore', 'solc-version': 'Ignore', 'suicidal': 'access_control', 'timestamp': 'time_manipulation', 'tx-origin': 'access_control', 'uninitialized-local': 'Other', 'uninitialized-state': 'Other', 'uninitialized-storage': 'Other', 'unused-return': 'unchecked_low_calls', 'unused-state': 'Ignore'}

        print(os.getcwd())


        print(f'{destiny_analysis}json/')
        print(f'{destiny_analysis}json_analysis/')
        print(f'{destiny_analysis}results/')
        print(f'{destiny_analysis}{version}_slither_{name}')



        ### Slither 
        # sa.run_analysis_diretory(diretory_in=source_solidity,diretory_out=destiny_analysis)

        # sa.resume_json(f'{destiny_analysis}json/',f'{destiny_analysis}json_analysis/')

        df = sa.build_dataframe_from_json(f'{destiny_analysis}json_analysis/',f'{destiny_analysis}results/')

        sa.sum_dataframe(df,f'{destiny_analysis}{version}_slither_{name}')

        df_dasp = sa.transform_dasp(dasp_dic,df,f'{destiny_analysis}{version}_slither_{name}')
        
        df_gabarito = pd.read_excel("helps/gabarito_dataset.xlsx").fillna(0)
        sa.accuracy2(df_dasp,df_gabarito,f'{destiny_analysis}')


    ### Mithril
    elif(analise=='m'):
        
        version='teste_0.24.7'        
        ma = MythrilAnalysis('0.4.26')
        destiny_analysis = f'./mythril/{version}_{name}/'
        dasp_dic = {'Write to Arbitrary Storage Location': 'access_control', 'Integer Overflow and Underflow': 'arithmetic', 'Timestamp Dependence': 'time_manipulation', 'Assert Violation': 'Other', 'Reentrancy': 'reentrancy', 'DoS with Failed': 'denial_service', 'Unprotected Ether Withdrawal': 'access_control', 'Delegatecall to Untrusted Callee': 'access_control', 'Authorization through tx.origin': 'access_control', 'Unchecked Call Return Value': 'unchecked_low_calls', 'Weak Sources of Randomness from Chain Attributes': 'bad_randomness', 'Unprotected SELFDESTRUCT Instruction': 'access_control', 'Transaction Order Dependence': 'front_running'}
        print(os.getcwd())


        print(f'{destiny_analysis}json/')
        print(f'{destiny_analysis}json_analysis/')
        print(f'{destiny_analysis}results/')
        print(f'{destiny_analysis}{version}_slither_{name}')



        ### Slither 
        # ma.run_analysis_diretory(diretory_in=source_solidity,diretory_out=destiny_analysis)

        # ma.resume_json(f'{destiny_analysis}json/',f'{destiny_analysis}json_analysis/')

        df = ma.build_dataframe_from_json(f'{destiny_analysis}json_analysis/',f'{destiny_analysis}results/')

        ma.sum_dataframe(df,f'{destiny_analysis}{version}_mythril_{name}')

        df_dasp = ma.transform_dasp(dasp_dic,df,f'{destiny_analysis}{version}_mythril_{name}')
        
        df_gabarito = pd.read_excel("helps/gabarito_dataset.xlsx").fillna(0)
        ma.accuracy2(df_dasp,df_gabarito,f'{destiny_analysis}')


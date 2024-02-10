import os
from slither.slither_analysis import SlitherAnalysis
from mythril.mythril_analysis import MythrilAnalysis
import pandas as pd 
from IPython.display import display, HTML

if '__main__'==__name__:

    
    name = 'smartbugs-curated'
    source_solidity = f'./repositories/{name}/'
  
    
    analise='m'

    if(analise=='s'):
        slither_version='0.8.0'    
        sa = SlitherAnalysis('0.4.26')
        destiny_analysis = f'./slither/{slither_version}_{name}/'
        dasp_dic = {'arbitrary-send': 'access_control', 'assembly': 'Ignore', 'calls-loop': 'denial_service', 'constable-states': 'Ignore', 'constant-function': 'Ignore', 'controlled-delegatecall': 'access_control', 'deprecated-standards': 'Ignore', 'erc20-indexed': 'Ignore', 'erc20-interface': 'Ignore', 'external-function': 'Ignore', 'incorrect-equality': 'Other', 'locked-ether': 'Other', 'low-level-calls': 'unchecked_low_calls', 'naming-convention': 'Ignore', 'reentrancy-benign': 'reentrancy', 'reentrancy-eth': 'reentrancy', 'reentrancy-no-eth': 'reentrancy', 'shadowing-abstract': 'Ignore', 'shadowing-builtin': 'Ignore', 'shadowing-local': 'Ignore', 'shadowing-state': 'Ignore', 'solc-version': 'Ignore', 'suicidal': 'access_control', 'timestamp': 'time_manipulation', 'tx-origin': 'access_control', 'uninitialized-local': 'Other', 'uninitialized-state': 'Other', 'uninitialized-storage': 'Other', 'unused-return': 'unchecked_low_calls', 'unused-state': 'Ignore'}

        print(os.getcwd())


        print(f'{destiny_analysis}json/')
        print(f'{destiny_analysis}json_analysis/')
        print(f'{destiny_analysis}results/')
        print(f'{destiny_analysis}{slither_version}_slither_{name}')



        ### Slither 
        # sa.run_analysis_diretory(diretory_in=source_solidity,diretory_out=destiny_analysis)

        # sa.resume_json(f'{destiny_analysis}json/',f'{destiny_analysis}json_analysis/')

        df = sa.montar_dataframe_json(f'{destiny_analysis}json_analysis/',f'{destiny_analysis}results/')
        
        df_dasp = sa.transforma_dasp(dasp_dic,df,f'{destiny_analysis}{slither_version}_slither_{name}')
        df_gabarito = pd.read_excel("helps/gabarito_dataset.xlsx").fillna(0)
        display(df_gabarito)
        sa.acurar(df_dasp,df_gabarito)

    ### Mithril
    elif(analise=='m'):
        mythril_version ='0.23.15'	
        dasp_dic = {'Call data forwarded with delegatecall()': 'access_control', 'DELEGATECALL to a user-supplied address': 'access_control', 'Dependence on predictable environment variable': 'Other', 'Dependence on predictable variable': 'Other', 'Ether send': 'access_control', 'Exception state': 'Other', 'Integer Overflow': 'arithmetic', 'Integer Underflow': 'arithmetic', 'Message call to external contract': 'reentrancy', 'Multiple Calls': 'Ignore', 'State change after external call': 'reentrancy', 'Transaction order dependence': 'front_running', 'Unchecked CALL return value': 'unchecked_low_calls', 'Unchecked SUICIDE': 'access_control', 'Use of tx.origin': 'access_control'}
        ma = MythrilAnalysis('0.4.26')
        destiny_analysis = f'./mythril/{mythril_version}_{name}/'
        print(os.getcwd())


        print(f'{destiny_analysis}json/')
        print(f'{destiny_analysis}json_analysis/')
        print(f'{destiny_analysis}results/')
        print(f'{destiny_analysis}{mythril_version}_slither_{name}')

       
        ma.run_analysis_diretory(diretory_in=source_solidity,diretory_out=destiny_analysis)

        ma.resume_json(f'{destiny_analysis}json/',f'{destiny_analysis}json_analysis/')

        df = ma.build_dataframe_from_json(f'{destiny_analysis}json_analysis/',f'{destiny_analysis}results/')
        
        df_dasp = ma.transform_dasp(dasp_dic,df,f'{destiny_analysis}{mythril_version}_slither_{name}')
        df_gabarito = pd.read_excel("helps/gabarito_dataset.xlsx").fillna(0)
        display(df_gabarito)
        ma.accuracy(df_dasp,df_gabarito,destiny_analysis)



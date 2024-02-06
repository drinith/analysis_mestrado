import os
from slither.slither_analysis import SlitherAnalysis
from mythril.mythril_analysis import MythrilAnalysis
import pandas as pd 
from IPython.display import display, HTML

if '__main__'==__name__:

    version='0.8.0'
    name = 'smartbugs-curated'
    source_solidity = f'./repositories/{name}/'
  
    
    analise='s'

    if(analise=='s'):
        
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

        df = sa.montar_dataframe_json(f'{destiny_analysis}json_analysis/',f'{destiny_analysis}results/')
        
        df_dasp = sa.transforma_dasp(dasp_dic,df,f'{destiny_analysis}{version}_slither_{name}')
        df_gabarito = pd.read_excel("helps/gabarito_dataset.xlsx").fillna(0)
        display(df_gabarito)
        sa.acurar(df_dasp,df_gabarito)

    ### Mithril
    elif(analise=='m'):
        
        ma = MythrilAnalysis('0.4.26')
        destiny_analysis = f'./mythril/{version}_{name}/'
        print(os.getcwd())


        print(f'{destiny_analysis}json/')
        print(f'{destiny_analysis}json_analysis/')
        print(f'{destiny_analysis}results/')
        print(f'{destiny_analysis}{version}_slither_{name}')



        ### Slither 
        ma.run_analysis_diretory(diretory_in=source_solidity,diretory_out=destiny_analysis)

        ma.resume_json(f'{destiny_analysis}json/',f'{destiny_analysis}json_analysis/')

        df = ma.montar_dataframe_json(f'{destiny_analysis}json_analysis/',f'{destiny_analysis}results/')

        ma.soma_dataframe(df,f'{destiny_analysis}{version}_slither_{name}')

       # ma.dasp(df,f'{destiny_analysis}{version}_slither_{name}')

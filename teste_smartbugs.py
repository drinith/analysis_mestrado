import os
from slither.slither_analysis import SlitherAnalysis
from mythril.mythril_analysis import MythrilAnalysis
import pandas as pd 
from IPython.display import display, HTML


if '__main__'==__name__:

    
    name = 'slither'
    source_solidity = f'./repositories/{name}/'
  
    
    analise='s'

    if(analise=='s'):
        
        sa = SlitherAnalysis('0.4.26')
        sa.resume_smartbugs_json(source_solidity,'./slither/analise_smartbugs_resultado')

    ### Mithril
    elif(analise=='m'):
        mythril_version ='0.23.15'	
        dasp_dic = {'Write to Arbitrary Storage Location': 'access_control', 'Integer Overflow and Underflow': 'arithmetic', 'Timestamp Dependence': 'time_manipulation', 'Assert Violation': 'Other', 'Reentrancy': 'reentrancy', 'DoS with Failed': 'denial_service', 'Unprotected Ether Withdrawal': 'access_control', 'Delegatecall to Untrusted Callee': 'Other', 'Authorization through tx.origin': 'access_control', 'Unchecked Call Return Value': 'unchecked_low_calls', 'Weak Sources of Randomness from Chain Attributes': 'bad_randomness', 'Unprotected SELFDESTRUCT Instruction': 'access_control', 'Transaction Order Dependence': 'Other'}
        ma = MythrilAnalysis('0.4.26')
        destiny_analysis = f'./mythril/{mythril_version}_{name}/'
        print(os.getcwd())


        print(f'{destiny_analysis}json/')
        print(f'{destiny_analysis}json_analysis/')
        print(f'{destiny_analysis}results/')
        print(f'{destiny_analysis}{mythril_version}_slither_{name}')

       
        # ma.run_analysis_diretory(diretory_in=source_solidity,diretory_out=destiny_analysis)

        # ma.resume_json(f'{destiny_analysis}json/',f'{destiny_analysis}json_analysis/')

        df = ma.build_dataframe_from_json(f'{destiny_analysis}json_analysis/',f'{destiny_analysis}results/')
        
        df_dasp = ma.transform_dasp(dasp_dic,df,f'{destiny_analysis}{mythril_version}_slither_{name}')
        df_gabarito = pd.read_excel("helps/gabarito_dataset.xlsx").fillna(0)
        display(df_gabarito)
        ma.accuracy(df_dasp,df_gabarito,destiny_analysis)


import os
from slither.slither_analysis import SlitherAnalysis
from mythril.mythril_analysis import MythrilAnalysis
import pandas as pd 
from IPython.display import display, HTML


if '__main__'==__name__:

    
    
    
    analise='m'

    if(analise=='s'):
        
        name = 'slither'
        source_solidity = f'./repositories/{name}/'
  

        dasp_dic = {'arbitrary-send': 'access_control', 'assembly': 'Ignore', 'calls-loop': 'denial_service', 'constable-states': 'Ignore', 'constant-function': 'Ignore', 'controlled-delegatecall': 'access_control', 'deprecated-standards': 'Ignore', 'erc20-indexed': 'Ignore', 'erc20-interface': 'Ignore', 'external-function': 'Ignore', 'incorrect-equality': 'Other', 'locked-ether': 'Other', 'low-level-calls': 'unchecked_low_calls', 'naming-convention': 'Ignore', 'reentrancy-benign': 'reentrancy', 'reentrancy-eth': 'reentrancy', 'reentrancy-no-eth': 'reentrancy', 'shadowing-abstract': 'Ignore', 'shadowing-builtin': 'Ignore', 'shadowing-local': 'Ignore', 'shadowing-state': 'Ignore', 'solc-version': 'Ignore', 'suicidal': 'access_control', 'timestamp': 'time_manipulation', 'tx-origin': 'access_control', 'uninitialized-local': 'Other', 'uninitialized-state': 'Other', 'uninitialized-storage': 'Other', 'unused-return': 'unchecked_low_calls', 'unused-state': 'Ignore'}
        sa = SlitherAnalysis('0.4.26')
        sa.resume_smartbugs_json(source_solidity,'./slither/analise_smartbugs_resultado')

        df = sa.build_dataframe_from_json('./slither/analise_smartbugs_resultado/','./slither/analise_smartbugs_resultado/')

        df_dasp = sa.transform_dasp(dasp_dic,df,f'./slither/analise_smartbugs_resultado/smartbugs_slither')
        df_gabarito = pd.read_excel("helps/gabarito_dataset.xlsx").fillna(0)
        sa.accuracy(df_dasp,df_gabarito,'./slither/analise_smartbugs_resultado')

    ### Mithril
    elif(analise=='m'):

        name = 'mythril'
        source_solidity = f'./repositories/{name}/'
  
        dasp_dic = {'Call data forwarded with delegatecall()': 'access_control', 'DELEGATECALL to a user-supplied address': 'access_control', 'Dependence on predictable environment variable': 'Other', 'Dependence on predictable variable': 'Other', 'Ether send': 'access_control', 'Exception state': 'Other', 'Integer Overflow ': 'arithmetic', 'Integer Underflow': 'arithmetic', 'Message call to external contract': 'reentrancy', 'Multiple Calls': 'Ignore', 'State change after external call': 'reentrancy', 'Transaction order dependence': 'front_running', 'Unchecked CALL return value': 'unchecked_low_calls', 'Unchecked SUICIDE': 'access_control', 'Use of tx.origin': 'access_control'} 
        #{'Write to Arbitrary Storage Location': 'access_control', 'Integer Overflow and Underflow': 'arithmetic', 'Timestamp Dependence': 'time_manipulation', 'Assert Violation': 'Other', 'Reentrancy': 'reentrancy', 'DoS with Failed': 'denial_service', 'Unprotected Ether Withdrawal': 'access_control', 'Delegatecall to Untrusted Callee': 'Other', 'Authorization through tx.origin': 'access_control', 'Unchecked Call Return Value': 'unchecked_low_calls', 'Weak Sources of Randomness from Chain Attributes': 'bad_randomness', 'Unprotected SELFDESTRUCT Instruction': 'access_control', 'Transaction Order Dependence': 'Other'}
        ma = MythrilAnalysis('0.4.26')
        ma.resume_smartbugs_json(source_solidity,'./mythril/analise_smartbugs_resultado')

        df = ma.build_dataframe_from_json('./mythril/analise_smartbugs_resultado/','./mythril/analise_smartbugs_resultado/')

        df_dasp = ma.transform_dasp(dasp_dic,df,f'./mythril/analise_smartbugs_resultado/smartbugs_mythril')
        df_gabarito = pd.read_excel("helps/gabarito_dataset.xlsx").fillna(0)
        ma.accuracy(df_dasp,df_gabarito,'./mythril/analise_smartbugs_resultado')




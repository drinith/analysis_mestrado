import os
from slither.slither_analysis import SlitherAnalysis
from mythril.mythril_analysis import MythrilAnalysis

if '__main__'==__name__:

    version='0.8.0'
    name = 'smartbugs-curated'
    source_solidity = f'./repositories/{name}/'
    destiny_analysis = f'./mythril/{version}_{name}/'
    
    analise='m'
    if(analise=='s'):
        
        sa = SlitherAnalysis('0.4.26')
        print(os.getcwd())


        print(f'{destiny_analysis}json/')
        print(f'{destiny_analysis}json_analysis/')
        print(f'{destiny_analysis}results/')
        print(f'{destiny_analysis}{version}_slither_{name}')



        ### Slither 
        sa.run_analysis_diretory(diretory_in=source_solidity,diretory_out=destiny_analysis)

        sa.resume_json(f'{destiny_analysis}json/',f'{destiny_analysis}json_analysis/')

        df = sa.montar_dataframe_json(f'{destiny_analysis}json_analysis/',f'{destiny_analysis}results/')

        sa.soma_dataframe(df,f'{destiny_analysis}{version}_slither_{name}')

        sa.dasp(df,f'{destiny_analysis}{version}_slither_{name}')

    ### Mithril
    elif(analise=='m'):
        
        ma = MythrilAnalysis('0.4.26')
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

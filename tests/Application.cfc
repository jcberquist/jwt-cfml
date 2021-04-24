component {

    rootPath = getDirectoryFromPath( getCurrentTemplatePath() ).replace( '\', '/', 'all' ).replaceNoCase( 'tests/', '' );

    this.mappings[ '/testbox' ] = rootPath & '/testbox';
    this.mappings[ '/models' ] = rootPath & '/models';

    public boolean function onRequestStart( String targetPage ) {
        setting requestTimeout="9999";
        return true;
    }

}

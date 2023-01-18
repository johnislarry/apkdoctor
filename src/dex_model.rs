use crate::dex_structs::{
    AnnotationItem, AnnotationSetItem, AnnotationSetRefList, AnnotationsDirectoryItem,
    CallSiteIdItem, ClassDataItem, ClassDefItem, CodeItem, DebugInfoItem, EncodedArrayItem,
    FieldIdItem, Header, HiddenapiClassDataItem, MapList, MethodHandleItem, MethodIdItem,
    ProtoIdItem, StringDataItem, StringIdItem, TypeIdItem, TypeList,
};

#[derive(Debug)]
pub struct DexModel {
    pub header: Header,
    pub string_ids: Vec<StringIdItem>,
    pub type_ids: Vec<TypeIdItem>,
    pub proto_ids: Vec<ProtoIdItem>,
    pub field_ids: Vec<FieldIdItem>,
    pub method_ids: Vec<MethodIdItem>,
    pub class_defs: Vec<ClassDefItem>,
    pub call_site_ids: Vec<CallSiteIdItem>,
    pub method_handles: Vec<MethodHandleItem>,
    pub type_lists: Vec<TypeList>,
    pub string_data_items: Vec<StringDataItem>,
    pub annotation_set_ref_lists: Vec<AnnotationSetRefList>,
    pub annotation_set_items: Vec<AnnotationSetItem>,
    pub annotation_items: Vec<AnnotationItem>,
    pub annotations_directory_items: Vec<AnnotationsDirectoryItem>,
    pub hiddenapi_class_data_items: Vec<HiddenapiClassDataItem>,
    pub encoded_array_items: Vec<EncodedArrayItem>,
    pub class_data_items: Vec<ClassDataItem>,
    pub debug_info_items: Vec<DebugInfoItem>,
    pub code_items: Vec<CodeItem>,
    pub link_data: Vec<u8>,
    pub map_list: MapList,
}

pub(crate) struct DexModelBuilder {
    header: Option<Header>,
    string_ids: Option<Vec<StringIdItem>>,
    type_ids: Option<Vec<TypeIdItem>>,
    proto_ids: Option<Vec<ProtoIdItem>>,
    field_ids: Option<Vec<FieldIdItem>>,
    method_ids: Option<Vec<MethodIdItem>>,
    class_defs: Option<Vec<ClassDefItem>>,
    call_site_ids: Option<Vec<CallSiteIdItem>>,
    method_handles: Option<Vec<MethodHandleItem>>,
    type_lists: Option<Vec<TypeList>>,
    string_data_items: Option<Vec<StringDataItem>>,
    annotation_set_ref_lists: Option<Vec<AnnotationSetRefList>>,
    annotation_set_items: Option<Vec<AnnotationSetItem>>,
    annotation_items: Option<Vec<AnnotationItem>>,
    annotations_directory_items: Option<Vec<AnnotationsDirectoryItem>>,
    hiddenapi_class_data_items: Option<Vec<HiddenapiClassDataItem>>,
    encoded_array_items: Option<Vec<EncodedArrayItem>>,
    class_data_items: Option<Vec<ClassDataItem>>,
    debug_info_items: Option<Vec<DebugInfoItem>>,
    code_items: Option<Vec<CodeItem>>,
    link_data: Option<Vec<u8>>,
    map_list: Option<MapList>,
}

impl DexModelBuilder {
    // TODO: simplify this with Default trait
    pub(crate) fn new() -> Self {
        Self {
            header: None,
            string_ids: None,
            type_ids: None,
            proto_ids: None,
            field_ids: None,
            method_ids: None,
            class_defs: None,
            call_site_ids: None,
            method_handles: None,
            type_lists: None,
            string_data_items: None,
            annotation_set_ref_lists: None,
            annotation_set_items: None,
            annotation_items: None,
            annotations_directory_items: None,
            hiddenapi_class_data_items: None,
            encoded_array_items: None,
            class_data_items: None,
            debug_info_items: None,
            code_items: None,
            link_data: None,
            map_list: None,
        }
    }

    pub(crate) fn set_header(&mut self, header: Header) {
        self.header = Some(header);
    }
    pub(crate) fn set_map_list(&mut self, map_list: MapList) {
        self.map_list = Some(map_list);
    }

    pub(crate) fn set_string_ids(&mut self, string_ids: Vec<StringIdItem>) {
        self.string_ids = Some(string_ids);
    }

    pub(crate) fn set_type_ids(&mut self, type_ids: Vec<TypeIdItem>) {
        self.type_ids = Some(type_ids);
    }

    pub(crate) fn set_proto_ids(&mut self, proto_ids: Vec<ProtoIdItem>) {
        self.proto_ids = Some(proto_ids);
    }

    pub(crate) fn set_field_ids(&mut self, field_ids: Vec<FieldIdItem>) {
        self.field_ids = Some(field_ids);
    }

    pub(crate) fn set_method_ids(&mut self, method_ids: Vec<MethodIdItem>) {
        self.method_ids = Some(method_ids);
    }

    pub(crate) fn set_class_defs(&mut self, class_defs: Vec<ClassDefItem>) {
        self.class_defs = Some(class_defs);
    }

    pub(crate) fn set_call_site_ids(&mut self, call_site_ids: Vec<CallSiteIdItem>) {
        self.call_site_ids = Some(call_site_ids);
    }

    pub(crate) fn set_method_handles(&mut self, method_handles: Vec<MethodHandleItem>) {
        self.method_handles = Some(method_handles);
    }

    pub(crate) fn set_type_lists(&mut self, type_lists: Vec<TypeList>) {
        self.type_lists = Some(type_lists);
    }

    pub(crate) fn set_string_data_items(&mut self, string_data_items: Vec<StringDataItem>) {
        self.string_data_items = Some(string_data_items);
    }

    pub(crate) fn set_annotation_set_ref_lists(
        &mut self,
        annotation_set_ref_lists: Vec<AnnotationSetRefList>,
    ) {
        self.annotation_set_ref_lists = Some(annotation_set_ref_lists);
    }

    pub(crate) fn set_annotation_set_items(
        &mut self,
        annotation_set_items: Vec<AnnotationSetItem>,
    ) {
        self.annotation_set_items = Some(annotation_set_items);
    }

    pub(crate) fn set_annotation_items(&mut self, annotation_items: Vec<AnnotationItem>) {
        self.annotation_items = Some(annotation_items);
    }

    pub(crate) fn set_annotations_directory_items(
        &mut self,
        annotations_directory_items: Vec<AnnotationsDirectoryItem>,
    ) {
        self.annotations_directory_items = Some(annotations_directory_items);
    }

    pub(crate) fn set_hiddenapi_class_data_items(
        &mut self,
        hiddenapi_class_data_items: Vec<HiddenapiClassDataItem>,
    ) {
        self.hiddenapi_class_data_items = Some(hiddenapi_class_data_items);
    }

    pub(crate) fn set_encoded_array_items(&mut self, encoded_array_items: Vec<EncodedArrayItem>) {
        self.encoded_array_items = Some(encoded_array_items);
    }

    pub(crate) fn set_class_data_items(&mut self, class_data_items: Vec<ClassDataItem>) {
        self.class_data_items = Some(class_data_items);
    }

    pub(crate) fn set_debug_info_items(&mut self, debug_info_items: Vec<DebugInfoItem>) {
        self.debug_info_items = Some(debug_info_items);
    }

    pub(crate) fn set_code_items(&mut self, code_items: Vec<CodeItem>) {
        self.code_items = Some(code_items);
    }

    pub(crate) fn set_link_data(&mut self, link_data: Vec<u8>) {
        self.link_data = Some(link_data);
    }

    /// Builds the DexModel.  Certain sections are considered optional, and if
    /// they are not set on the builder, a default empty vector is used.
    pub(crate) fn build(self) -> DexModel {
        return DexModel {
            header: self.header.unwrap(),
            string_ids: self.string_ids.unwrap_or_default(),
            type_ids: self.type_ids.unwrap_or_default(),
            proto_ids: self.proto_ids.unwrap_or_default(),
            field_ids: self.field_ids.unwrap_or_default(),
            method_ids: self.method_ids.unwrap_or_default(),
            class_defs: self.class_defs.unwrap_or_default(),
            call_site_ids: self.call_site_ids.unwrap_or_default(),
            method_handles: self.method_handles.unwrap_or_default(),
            string_data_items: self.string_data_items.unwrap_or_default(),
            type_lists: self.type_lists.unwrap_or_default(),
            annotation_set_ref_lists: self.annotation_set_ref_lists.unwrap_or_default(),
            annotation_set_items: self.annotation_set_items.unwrap_or_default(),
            annotation_items: self.annotation_items.unwrap_or_default(),
            annotations_directory_items: self.annotations_directory_items.unwrap_or_default(),
            hiddenapi_class_data_items: self.hiddenapi_class_data_items.unwrap_or_default(),
            encoded_array_items: self.encoded_array_items.unwrap_or_default(),
            class_data_items: self.class_data_items.unwrap_or_default(),
            debug_info_items: self.debug_info_items.unwrap_or_default(),
            code_items: self.code_items.unwrap_or_default(),
            link_data: self.link_data.unwrap_or_default(),
            map_list: self.map_list.unwrap(),
        };
    }
}

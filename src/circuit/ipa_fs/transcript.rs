use franklin_crypto::babyjubjub::JubjubEngine;
use franklin_crypto::bellman::plonk::better_better_cs::cs::ConstraintSystem;
use franklin_crypto::bellman::SynthesisError;
use franklin_crypto::plonk::circuit::allocated_num::AllocatedNum;
use franklin_crypto::plonk::circuit::bigint::field::{FieldElement, RnsParameters};
use verkle_tree::ff_utils::bn256_fs::Bn256Fs;
use verkle_tree::ipa_fr::utils::{read_field_element_le, write_field_element_le};
use verkle_tree::ipa_fs::transcript::{from_bytes_le, to_bytes_le};

use crate::circuit::num::baby_ecc::EdwardsPoint;
use crate::circuit::poseidon_fs::calc_poseidon;

use super::utils::{convert_fr_to_fs, convert_fs_to_fr};

pub fn convert_ff_to_ff_ce<E: JubjubEngine>(value: Bn256Fs) -> anyhow::Result<E::Fs> {
    read_field_element_le::<E::Fs>(&to_bytes_le(&value))
}

pub fn convert_ff_ce_to_ff<E: JubjubEngine>(value: E::Fs) -> anyhow::Result<Bn256Fs> {
    from_bytes_le(&write_field_element_le(&value))
}

pub trait Transcript<E: JubjubEngine>: Sized + Clone {
    type Params;

    fn new<CS: ConstraintSystem<E>>(cs: &mut CS, init_state: Self::Params) -> Self;
    fn commit_field_element<'a, CS: ConstraintSystem<E>>(
        &mut self,
        cs: &mut CS,
        element: &FieldElement<'a, E, E::Fs>,
    ) -> Result<(), SynthesisError>;
    fn commit_point<CS: ConstraintSystem<E>>(
        &mut self,
        cs: &mut CS,
        point: &EdwardsPoint<E>,
    ) -> Result<(), SynthesisError>;
    fn get_challenge<'a, CS: ConstraintSystem<E>>(
        &mut self,
        cs: &mut CS,
        rns_params: &'a RnsParameters<E, E::Fs>,
    ) -> Result<FieldElement<'a, E, E::Fs>, SynthesisError>;
    fn into_params(self) -> Self::Params;
}

#[derive(Clone)]
pub struct WrappedTranscript<E>
where
    E: JubjubEngine,
{
    state: AllocatedNum<E>,
}

impl<E> Transcript<E> for WrappedTranscript<E>
where
    E: JubjubEngine,
{
    type Params = AllocatedNum<E>;

    fn new<CS: ConstraintSystem<E>>(_cs: &mut CS, init_state: AllocatedNum<E>) -> Self {
        Self { state: init_state }
    }

    fn commit_field_element<'a, CS: ConstraintSystem<E>>(
        &mut self,
        cs: &mut CS,
        element: &FieldElement<'a, E, E::Fs>,
    ) -> Result<(), SynthesisError> {
        let element_fr = element
            .get_field_value()
            .map(|e| convert_fs_to_fr::<E>(&e).unwrap());
        let wrapped_element = AllocatedNum::<E>::alloc(cs, || {
            element_fr.ok_or(SynthesisError::UnconstrainedVariable)
        })?;
        self.commit_alloc_num(cs, &wrapped_element)?;

        Ok(())
    }

    /// Commit a `WP` value.

    fn commit_point<CS: ConstraintSystem<E>>(
        &mut self,
        cs: &mut CS,
        point: &EdwardsPoint<E>,
    ) -> Result<(), SynthesisError> {
        let point_x = point.get_x();
        self.commit_alloc_num(cs, point_x)?;
        let point_y = point.get_y();
        self.commit_alloc_num(cs, point_y)?;

        Ok(())
    }

    fn get_challenge<'a, CS: ConstraintSystem<E>>(
        &mut self,
        cs: &mut CS,
        rns_params: &'a RnsParameters<E, E::Fs>,
    ) -> Result<FieldElement<'a, E, E::Fs>, SynthesisError> {
        let result = convert_fr_to_fs(cs, &self.state).unwrap();
        let wrapped_result = FieldElement::new_allocated_in_field(cs, result, rns_params)?;

        Ok(wrapped_result)
    }

    fn into_params(self) -> AllocatedNum<E> {
        self.state
    }
}

impl<E> WrappedTranscript<E>
where
    E: JubjubEngine,
{
    /// Commit a `AllocatedNum` value.
    fn commit_alloc_num<CS: ConstraintSystem<E>>(
        &mut self,
        cs: &mut CS,
        element: &AllocatedNum<E>,
    ) -> Result<(), SynthesisError> {
        let inputs = vec![self.state, *element];
        self.state = calc_poseidon::<E, CS>(cs, &inputs)?;

        Ok(())
    }
}

// const T: usize = 3;
// // const n_rounds_p: [usize; 8] = [56, 57, 56, 60, 60, 63, 64, 63];
// const N_ROUNDS_F: usize = 8;
// const N_ROUNDS_P: usize = 57; // n_rounds_p[T - 2];

// const C: [&str; /* n_rounds_p */ 195] = [
//   "0x0ee9a592ba9a9518d05986d656f40c2114c4993c11bb29938d21d47304cd8e6e", "0x00f1445235f2148c5986587169fc1bcd887b08d4d00868df5696fff40956e864", "0x08dff3487e8ac99e1f29a058d0fa80b930c728730b7ab36ce879f3890ecf73f5", "0x2f27be690fdaee46c3ce28f7532b13c856c35342c84bda6e20966310fadc01d0", "0x2b2ae1acf68b7b8d2416bebf3d4f6234b763fe04b8043ee48b8327bebca16cf2", "0x0319d062072bef7ecca5eac06f97d4d55952c175ab6b03eae64b44c7dbf11cfa", "0x28813dcaebaeaa828a376df87af4a63bc8b7bf27ad49c6298ef7b387bf28526d", "0x2727673b2ccbc903f181bf38e1c1d40d2033865200c352bc150928adddf9cb78", "0x234ec45ca27727c2e74abd2b2a1494cd6efbd43e340587d6b8fb9e31e65cc632", "0x15b52534031ae18f7f862cb2cf7cf760ab10a8150a337b1ccd99ff6e8797d428", "0x0dc8fad6d9e4b35f5ed9a3d186b79ce38e0e8a8d1b58b132d701d4eecf68d1f6", "0x1bcd95ffc211fbca600f705fad3fb567ea4eb378f62e1fec97805518a47e4d9c", "0x10520b0ab721cadfe9eff81b016fc34dc76da36c2578937817cb978d069de559", "0x1f6d48149b8e7f7d9b257d8ed5fbbaf42932498075fed0ace88a9eb81f5627f6", "0x1d9655f652309014d29e00ef35a2089bfff8dc1c816f0dc9ca34bdb5460c8705", "0x04df5a56ff95bcafb051f7b1cd43a99ba731ff67e47032058fe3d4185697cc7d", "0x0672d995f8fff640151b3d290cedaf148690a10a8c8424a7f6ec282b6e4be828", "0x099952b414884454b21200d7ffafdd5f0c9a9dcc06f2708e9fc1d8209b5c75b9", "0x052cba2255dfd00c7c483143ba8d469448e43586a9b4cd9183fd0e843a6b9fa6", "0x0b8badee690adb8eb0bd74712b7999af82de55707251ad7716077cb93c464ddc", "0x119b1590f13307af5a1ee651020c07c749c15d60683a8050b963d0a8e4b2bdd1", "0x03150b7cd6d5d17b2529d36be0f67b832c4acfc884ef4ee5ce15be0bfb4a8d09", "0x2cc6182c5e14546e3cf1951f173912355374efb83d80898abe69cb317c9ea565", "0x005032551e6378c450cfe129a404b3764218cadedac14e2b92d2cd73111bf0f9", "0x233237e3289baa34bb147e972ebcb9516469c399fcc069fb88f9da2cc28276b5", "0x05c8f4f4ebd4a6e3c980d31674bfbe6323037f21b34ae5a4e80c2d4c24d60280", "0x0a7b1db13042d396ba05d818a319f25252bcf35ef3aeed91ee1f09b2590fc65b", "0x2a73b71f9b210cf5b14296572c9d32dbf156e2b086ff47dc5df542365a404ec0", "0x1ac9b0417abcc9a1935107e9ffc91dc3ec18f2c4dbe7f22976a760bb5c50c460", "0x12c0339ae08374823fabb076707ef479269f3e4d6cb104349015ee046dc93fc0", "0x0b7475b102a165ad7f5b18db4e1e704f52900aa3253baac68246682e56e9a28e", "0x037c2849e191ca3edb1c5e49f6e8b8917c843e379366f2ea32ab3aa88d7f8448", "0x05a6811f8556f014e92674661e217e9bd5206c5c93a07dc145fdb176a716346f", "0x29a795e7d98028946e947b75d54e9f044076e87a7b2883b47b675ef5f38bd66e", "0x20439a0c84b322eb45a3857afc18f5826e8c7382c8a1585c507be199981fd22f", "0x2e0ba8d94d9ecf4a94ec2050c7371ff1bb50f27799a84b6d4a2a6f2a0982c887", "0x143fd115ce08fb27ca38eb7cce822b4517822cd2109048d2e6d0ddcca17d71c8", "0x0c64cbecb1c734b857968dbbdcf813cdf8611659323dbcbfc84323623be9caf1", "0x028a305847c683f646fca925c163ff5ae74f348d62c2b670f1426cef9403da53", "0x2e4ef510ff0b6fda5fa940ab4c4380f26a6bcb64d89427b824d6755b5db9e30c", "0x0081c95bc43384e663d79270c956ce3b8925b4f6d033b078b96384f50579400e", "0x2ed5f0c91cbd9749187e2fade687e05ee2491b349c039a0bba8a9f4023a0bb38", "0x30509991f88da3504bbf374ed5aae2f03448a22c76234c8c990f01f33a735206", "0x1c3f20fd55409a53221b7c4d49a356b9f0a1119fb2067b41a7529094424ec6ad", "0x10b4e7f3ab5df003049514459b6e18eec46bb2213e8e131e170887b47ddcb96c", "0x2a1982979c3ff7f43ddd543d891c2abddd80f804c077d775039aa3502e43adef", "0x1c74ee64f15e1db6feddbead56d6d55dba431ebc396c9af95cad0f1315bd5c91", "0x07533ec850ba7f98eab9303cace01b4b9e4f2e8b82708cfa9c2fe45a0ae146a0", "0x21576b438e500449a151e4eeaf17b154285c68f42d42c1808a11abf3764c0750", "0x2f17c0559b8fe79608ad5ca193d62f10bce8384c815f0906743d6930836d4a9e", "0x2d477e3862d07708a79e8aae946170bc9775a4201318474ae665b0b1b7e2730e", "0x162f5243967064c390e095577984f291afba2266c38f5abcd89be0f5b2747eab", "0x2b4cb233ede9ba48264ecd2c8ae50d1ad7a8596a87f29f8a7777a70092393311", "0x2c8fbcb2dd8573dc1dbaf8f4622854776db2eece6d85c4cf4254e7c35e03b07a", "0x1d6f347725e4816af2ff453f0cd56b199e1b61e9f601e9ade5e88db870949da9", "0x204b0c397f4ebe71ebc2d8b3df5b913df9e6ac02b68d31324cd49af5c4565529", "0x0c4cb9dc3c4fd8174f1149b3c63c3c2f9ecb827cd7dc25534ff8fb75bc79c502", "0x174ad61a1448c899a25416474f4930301e5c49475279e0639a616ddc45bc7b54", "0x1a96177bcf4d8d89f759df4ec2f3cde2eaaa28c177cc0fa13a9816d49a38d2ef", "0x066d04b24331d71cd0ef8054bc60c4ff05202c126a233c1a8242ace360b8a30a", "0x2a4c4fc6ec0b0cf52195782871c6dd3b381cc65f72e02ad527037a62aa1bd804", "0x13ab2d136ccf37d447e9f2e14a7cedc95e727f8446f6d9d7e55afc01219fd649", "0x1121552fca26061619d24d843dc82769c1b04fcec26f55194c2e3e869acc6a9a", "0x00ef653322b13d6c889bc81715c37d77a6cd267d595c4a8909a5546c7c97cff1", "0x0e25483e45a665208b261d8ba74051e6400c776d652595d9845aca35d8a397d3", "0x29f536dcb9dd7682245264659e15d88e395ac3d4dde92d8c46448db979eeba89", "0x2a56ef9f2c53febadfda33575dbdbd885a124e2780bbea170e456baace0fa5be", "0x1c8361c78eb5cf5decfb7a2d17b5c409f2ae2999a46762e8ee416240a8cb9af1", "0x151aff5f38b20a0fc0473089aaf0206b83e8e68a764507bfd3d0ab4be74319c5", "0x04c6187e41ed881dc1b239c88f7f9d43a9f52fc8c8b6cdd1e76e47615b51f100", "0x13b37bd80f4d27fb10d84331f6fb6d534b81c61ed15776449e801b7ddc9c2967", "0x01a5c536273c2d9df578bfbd32c17b7a2ce3664c2a52032c9321ceb1c4e8a8e4", "0x2ab3561834ca73835ad05f5d7acb950b4a9a2c666b9726da832239065b7c3b02", "0x1d4d8ec291e720db200fe6d686c0d613acaf6af4e95d3bf69f7ed516a597b646", "0x041294d2cc484d228f5784fe7919fd2bb925351240a04b711514c9c80b65af1d", "0x154ac98e01708c611c4fa715991f004898f57939d126e392042971dd90e81fc6", "0x0b339d8acca7d4f83eedd84093aef51050b3684c88f8b0b04524563bc6ea4da4", "0x0955e49e6610c94254a4f84cfbab344598f0e71eaff4a7dd81ed95b50839c82e", "0x06746a6156eba54426b9e22206f15abca9a6f41e6f535c6f3525401ea0654626", "0x0f18f5a0ecd1423c496f3820c549c27838e5790e2bd0a196ac917c7ff32077fb", "0x04f6eeca1751f7308ac59eff5beb261e4bb563583ede7bc92a738223d6f76e13", "0x2b56973364c4c4f5c1a3ec4da3cdce038811eb116fb3e45bc1768d26fc0b3758", "0x123769dd49d5b054dcd76b89804b1bcb8e1392b385716a5d83feb65d437f29ef", "0x2147b424fc48c80a88ee52b91169aacea989f6446471150994257b2fb01c63e9", "0x0fdc1f58548b85701a6c5505ea332a29647e6f34ad4243c2ea54ad897cebe54d", "0x12373a8251fea004df68abcf0f7786d4bceff28c5dbbe0c3944f685cc0a0b1f2", "0x21e4f4ea5f35f85bad7ea52ff742c9e8a642756b6af44203dd8a1f35c1a90035", "0x16243916d69d2ca3dfb4722224d4c462b57366492f45e90d8a81934f1bc3b147", "0x1efbe46dd7a578b4f66f9adbc88b4378abc21566e1a0453ca13a4159cac04ac2", "0x07ea5e8537cf5dd08886020e23a7f387d468d5525be66f853b672cc96a88969a", "0x05a8c4f9968b8aa3b7b478a30f9a5b63650f19a75e7ce11ca9fe16c0b76c00bc", "0x20f057712cc21654fbfe59bd345e8dac3f7818c701b9c7882d9d57b72a32e83f", "0x04a12ededa9dfd689672f8c67fee31636dcd8e88d01d49019bd90b33eb33db69", "0x27e88d8c15f37dcee44f1e5425a51decbd136ce5091a6767e49ec9544ccd101a", "0x2feed17b84285ed9b8a5c8c5e95a41f66e096619a7703223176c41ee433de4d1", "0x1ed7cc76edf45c7c404241420f729cf394e5942911312a0d6972b8bd53aff2b8", "0x15742e99b9bfa323157ff8c586f5660eac6783476144cdcadf2874be45466b1a", "0x1aac285387f65e82c895fc6887ddf40577107454c6ec0317284f033f27d0c785", "0x25851c3c845d4790f9ddadbdb6057357832e2e7a49775f71ec75a96554d67c77", "0x15a5821565cc2ec2ce78457db197edf353b7ebba2c5523370ddccc3d9f146a67", "0x2411d57a4813b9980efa7e31a1db5966dcf64f36044277502f15485f28c71727", "0x002e6f8d6520cd4713e335b8c0b6d2e647e9a98e12f4cd2558828b5ef6cb4c9b", "0x2ff7bc8f4380cde997da00b616b0fcd1af8f0e91e2fe1ed7398834609e0315d2", "0x00b9831b948525595ee02724471bcd182e9521f6b7bb68f1e93be4febb0d3cbe", "0x0a2f53768b8ebf6a86913b0e57c04e011ca408648a4743a87d77adbf0c9c3512", "0x00248156142fd0373a479f91ff239e960f599ff7e94be69b7f2a290305e1198d", "0x171d5620b87bfb1328cf8c02ab3f0c9a397196aa6a542c2350eb512a2b2bcda9", "0x170a4f55536f7dc970087c7c10d6fad760c952172dd54dd99d1045e4ec34a808", "0x29aba33f799fe66c2ef3134aea04336ecc37e38c1cd211ba482eca17e2dbfae1", "0x1e9bc179a4fdd758fdd1bb1945088d47e70d114a03f6a0e8b5ba650369e64973", "0x1dd269799b660fad58f7f4892dfb0b5afeaad869a9c4b44f9c9e1c43bdaf8f09", "0x22cdbc8b70117ad1401181d02e15459e7ccd426fe869c7c95d1dd2cb0f24af38", "0x0ef042e454771c533a9f57a55c503fcefd3150f52ed94a7cd5ba93b9c7dacefd", "0x11609e06ad6c8fe2f287f3036037e8851318e8b08a0359a03b304ffca62e8284", "0x1166d9e554616dba9e753eea427c17b7fecd58c076dfe42708b08f5b783aa9af", "0x2de52989431a859593413026354413db177fbf4cd2ac0b56f855a888357ee466", "0x3006eb4ffc7a85819a6da492f3a8ac1df51aee5b17b8e89d74bf01cf5f71e9ad", "0x2af41fbb61ba8a80fdcf6fff9e3f6f422993fe8f0a4639f962344c8225145086", "0x119e684de476155fe5a6b41a8ebc85db8718ab27889e85e781b214bace4827c3", "0x1835b786e2e8925e188bea59ae363537b51248c23828f047cff784b97b3fd800", "0x28201a34c594dfa34d794996c6433a20d152bac2a7905c926c40e285ab32eeb6", "0x083efd7a27d1751094e80fefaf78b000864c82eb571187724a761f88c22cc4e7", "0x0b6f88a3577199526158e61ceea27be811c16df7774dd8519e079564f61fd13b", "0x0ec868e6d15e51d9644f66e1d6471a94589511ca00d29e1014390e6ee4254f5b", "0x2af33e3f866771271ac0c9b3ed2e1142ecd3e74b939cd40d00d937ab84c98591", "0x0b520211f904b5e7d09b5d961c6ace7734568c547dd6858b364ce5e47951f178", "0x0b2d722d0919a1aad8db58f10062a92ea0c56ac4270e822cca228620188a1d40", "0x1f790d4d7f8cf094d980ceb37c2453e957b54a9991ca38bbe0061d1ed6e562d4", "0x0171eb95dfbf7d1eaea97cd385f780150885c16235a2a6a8da92ceb01e504233", "0x0c2d0e3b5fd57549329bf6885da66b9b790b40defd2c8650762305381b168873", "0x1162fb28689c27154e5a8228b4e72b377cbcafa589e283c35d3803054407a18d", "0x2f1459b65dee441b64ad386a91e8310f282c5a92a89e19921623ef8249711bc0", "0x1e6ff3216b688c3d996d74367d5cd4c1bc489d46754eb712c243f70d1b53cfbb", "0x01ca8be73832b8d0681487d27d157802d741a6f36cdc2a0576881f9326478875", "0x1f7735706ffe9fc586f976d5bdf223dc680286080b10cea00b9b5de315f9650e", "0x2522b60f4ea3307640a0c2dce041fba921ac10a3d5f096ef4745ca838285f019", "0x23f0bee001b1029d5255075ddc957f833418cad4f52b6c3f8ce16c235572575b", "0x2bc1ae8b8ddbb81fcaac2d44555ed5685d142633e9df905f66d9401093082d59", "0x0f9406b8296564a37304507b8dba3ed162371273a07b1fc98011fcd6ad72205f", "0x2360a8eb0cc7defa67b72998de90714e17e75b174a52ee4acb126c8cd995f0a8", "0x15871a5cddead976804c803cbaef255eb4815a5e96df8b006dcbbc2767f88948", "0x193a56766998ee9e0a8652dd2f3b1da0362f4f54f72379544f957ccdeefb420f", "0x2a394a43934f86982f9be56ff4fab1703b2e63c8ad334834e4309805e777ae0f", "0x1859954cfeb8695f3e8b635dcb345192892cd11223443ba7b4166e8876c0d142", "0x04e1181763050e58013444dbcb99f1902b11bc25d90bbdca408d3819f4fed32b", "0x0fdb253dee83869d40c335ea64de8c5bb10eb82db08b5e8b1f5e5552bfd05f23", "0x058cbe8a9a5027bdaa4efb623adead6275f08686f1c08984a9d7c5bae9b4f1c0", "0x1382edce9971e186497eadb1aeb1f52b23b4b83bef023ab0d15228b4cceca59a", "0x03464990f045c6ee0819ca51fd11b0be7f61b8eb99f14b77e1e6634601d9e8b5", "0x23f7bfc8720dc296fff33b41f98ff83c6fcab4605db2eb5aaa5bc137aeb70a58", "0x0a59a158e3eec2117e6e94e7f0e9decf18c3ffd5e1531a9219636158bbaf62f2", "0x06ec54c80381c052b58bf23b312ffd3ce2c4eba065420af8f4c23ed0075fd07b", "0x118872dc832e0eb5476b56648e867ec8b09340f7a7bcb1b4962f0ff9ed1f9d01", "0x13d69fa127d834165ad5c7cba7ad59ed52e0b0f0e42d7fea95e1906b520921b1", "0x169a177f63ea681270b1c6877a73d21bde143942fb71dc55fd8a49f19f10c77b", "0x04ef51591c6ead97ef42f287adce40d93abeb032b922f66ffb7e9a5a7450544d", "0x256e175a1dc079390ecd7ca703fb2e3b19ec61805d4f03ced5f45ee6dd0f69ec", "0x30102d28636abd5fe5f2af412ff6004f75cc360d3205dd2da002813d3e2ceeb2", "0x10998e42dfcd3bbf1c0714bc73eb1bf40443a3fa99bef4a31fd31be182fcc792", "0x193edd8e9fcf3d7625fa7d24b598a1d89f3362eaf4d582efecad76f879e36860", "0x18168afd34f2d915d0368ce80b7b3347d1c7a561ce611425f2664d7aa51f0b5d", "0x29383c01ebd3b6ab0c017656ebe658b6a328ec77bc33626e29e2e95b33ea6111", "0x10646d2f2603de39a1f4ae5e7771a64a702db6e86fb76ab600bf573f9010c711", "0x0beb5e07d1b27145f575f1395a55bf132f90c25b40da7b3864d0242dcb1117fb", "0x16d685252078c133dc0d3ecad62b5c8830f95bb2e54b59abdffbf018d96fa336", "0x0a6abd1d833938f33c74154e0404b4b40a555bbbec21ddfafd672dd62047f01a", "0x1a679f5d36eb7b5c8ea12a4c2dedc8feb12dffeec450317270a6f19b34cf1860", "0x0980fb233bd456c23974d50e0ebfde4726a423eada4e8f6ffbc7592e3f1b93d6", "0x161b42232e61b84cbf1810af93a38fc0cece3d5628c9282003ebacb5c312c72b", "0x0ada10a90c7f0520950f7d47a60d5e6a493f09787f1564e5d09203db47de1a0b", "0x1a730d372310ba82320345a29ac4238ed3f07a8a2b4e121bb50ddb9af407f451", "0x2c8120f268ef054f817064c369dda7ea908377feaba5c4dffbda10ef58e8c556", "0x1c7c8824f758753fa57c00789c684217b930e95313bcb73e6e7b8649a4968f70", "0x2cd9ed31f5f8691c8e39e4077a74faa0f400ad8b491eb3f7b47b27fa3fd1cf77", "0x23ff4f9d46813457cf60d92f57618399a5e022ac321ca550854ae23918a22eea", "0x09945a5d147a4f66ceece6405dddd9d0af5a2c5103529407dff1ea58f180426d", "0x188d9c528025d4c2b67660c6b771b90f7c7da6eaa29d3f268a6dd223ec6fc630", "0x3050e37996596b7f81f68311431d8734dba7d926d3633595e0c0d8ddf4f0f47f", "0x15af1169396830a91600ca8102c35c426ceae5461e3f95d89d829518d30afd78", "0x1da6d09885432ea9a06d9f37f873d985dae933e351466b2904284da3320d8acc", "0x2796ea90d269af29f5f8acf33921124e4e4fad3dbe658945e546ee411ddaa9cb", "0x202d7dd1da0f6b4b0325c8b3307742f01e15612ec8e9304a7cb0319e01d32d60", "0x096d6790d05bb759156a952ba263d672a2d7f9c788f4c831a29dace4c0f8be5f", "0x054efa1f65b0fce283808965275d877b438da23ce5b13e1963798cb1447d25a4", "0x1b162f83d917e93edb3308c29802deb9d8aa690113b2e14864ccf6e18e4165f1", "0x21e5241e12564dd6fd9f1cdd2a0de39eedfefc1466cc568ec5ceb745a0506edc", "0x1cfb5662e8cf5ac9226a80ee17b36abecb73ab5f87e161927b4349e10e4bdf08", "0x0f21177e302a771bbae6d8d1ecb373b62c99af346220ac0129c53f666eb24100", "0x1671522374606992affb0dd7f71b12bec4236aede6290546bcef7e1f515c2320", "0x0fa3ec5b9488259c2eb4cf24501bfad9be2ec9e42c5cc8ccd419d2a692cad870", "0x193c0e04e0bd298357cb266c1506080ed36edce85c648cc085e8c57b1ab54bba", "0x102adf8ef74735a27e9128306dcbc3c99f6f7291cd406578ce14ea2adaba68f8", "0x0fe0af7858e49859e2a54d6f1ad945b1316aa24bfbdd23ae40a6d0cb70c3eab1", "0x216f6717bbc7dedb08536a2220843f4e2da5f1daa9ebdefde8a5ea7344798d22", "0x1da55cc900f0d21f4a3e694391918a1b3c23b2ac773c6b3ef88e2e4228325161"
// ];

// const M: [[&str; T]; T] = [
//     [
//         "0x109b7f411ba0e4c9b2b70caf5c36a7b194be7c11ad24378bfedb68592ba8118b",
//         "0x16ed41e13bb9c0c66ae119424fddbcbc9314dc9fdbdeea55d6c64543dc4903e0",
//         "0x2b90bba00fca0589f617e7dcbfe82e0df706ab640ceb247b791a93b74e36736d",
//     ],
//     [
//         "0x2969f27eed31a480b9c36c764379dbca2cc8fdd1415c3dded62940bcde0bd771",
//         "0x2e2419f9ec02ec394c9871c832963dc1b89d743c8c7b964029b2311687b1fe23",
//         "0x101071f0032379b697315876690f053d148d4e109f5fb065c8aacc55a0f89bfa",
//     ],
//     [
//         "0x143021ec686a3f330d5f9e654638065ce6cd79e28c5b3753326244ee65a1b1a7",
//         "0x176cc029695ad02582a70eff08a6fd99d057e12e58e7d7b6b16cdfabc8ee2911",
//         "0x19a3fc0a56702bf417ba7fee3802593fa644470307043f7773279cd71d25d5e0",
//     ],
// ];

// #[derive(Clone)]
// pub struct SigmaCircuit<'a, E: JubjubEngine> {
//     pub input: FieldElement<'a, E, E::Fs>,
//     pub output: FieldElement<'a, E, E::Fs>,
// }

// // out = input^5
// impl<'a, E: JubjubEngine> SigmaCircuit<'a, E> {
//     // pub fn default() -> Self {
//     //     Self {
//     //         input: None,
//     //         output: None,
//     //     }
//     // }

//     pub fn run<CS>(&mut self, cs: &mut CS) -> Result<(), SynthesisError>
//     where
//         CS: ConstraintSystem<E>,
//     {
//         let input = self.input;
//         let input2 = input.mul(cs, input)?;
//         let input4 = input2.mul(cs.namespace(|| "compute input4"), &input2)?;
//         let input5 = input4.mul(cs.namespace(|| "compute input5"), &input)?;
//         self.output = input5.get_value();

//         Ok(())
//     }
// }

// #[derive(Clone)]
// pub struct ArkCircuit<E: JubjubEngine> {
//     pub inputs: Vec<Option<E::Fr>>,
//     pub outputs: Vec<Option<E::Fr>>,
//     pub width: usize,
//     pub round: usize,
// }

// impl<E: JubjubEngine> ArkCircuit<E> {
//     pub fn with_capacity(capacity: usize, round: usize) -> Self {
//         Self {
//             inputs: vec![None; capacity],
//             outputs: vec![None; capacity],
//             width: capacity,
//             round,
//         }
//     }

//     pub fn run<CS>(&mut self, mut cs: CS) -> Result<(), SynthesisError>
//     where
//         CS: ConstraintSystem<E>,
//     {
//         assert_eq!(self.inputs.len(), self.width, "invalid inputs length");

//         for i in 0..self.width {
//             let inputs_i: AllocatedNum<E> =
//                 AllocatedNum::alloc(cs.namespace(|| format!("allocate inputs[{}]", i)), || {
//                     Ok(self.inputs[i].unwrap())
//                     // self.inputs[i].ok_or(SynthesisError::UnconstrainedVariable)
//                 })?;
//             let c = read_field_element_be::<E::Fr>(&hex::decode(&C[i + self.round][2..]).unwrap())
//                 .unwrap();
//             let output_i =
//                 inputs_i.add_constant(cs.namespace(|| format!("add inputs[{}] to c", i)), c)?;
//             self.outputs[i] = output_i.get_value();
//         }

//         Ok(())
//     }
// }

// #[derive(Clone)]
// pub struct MixCircuit<E: JubjubEngine> {
//     pub inputs: Vec<Option<E::Fr>>,
//     pub outputs: Vec<Option<E::Fr>>,
//     pub width: usize,
// }

// impl<E: JubjubEngine> MixCircuit<E> {
//     pub fn with_capacity(capacity: usize) -> Self {
//         Self {
//             inputs: vec![None; capacity],
//             outputs: vec![None; capacity],
//             width: capacity,
//         }
//     }

//     pub fn run<CS>(&mut self, mut cs: CS) -> Result<(), SynthesisError>
//     where
//         CS: ConstraintSystem<E>,
//     {
//         assert_eq!(self.inputs.len(), self.width, "invalid inputs length");

//         let zero = AllocatedNum::zero(cs.namespace(|| "allocate zero"))?;
//         for i in 0..self.width {
//             let mut lc = zero.clone();
//             for (j, inputs_j) in self.inputs.iter().enumerate() {
//                 let m =
//                     read_field_element_be::<E::Fr>(&hex::decode(&M[j][i][2..]).unwrap()).unwrap();
//                 let wrapped_m = AllocatedNum::alloc(
//                     cs.namespace(|| format!("allocate M[{}][{}]", j, i)),
//                     || Ok(m),
//                 )?;
//                 let inputs_j = AllocatedNum::alloc(
//                     cs.namespace(|| format!("allocate inputs[{}][{}]", j, i)),
//                     || {
//                         Ok(inputs_j.unwrap())
//                         // self.inputs[j].ok_or(SynthesisError::UnconstrainedVariable)
//                     },
//                 )?; // TODO: uncheck
//                 let tmp = wrapped_m.mul(
//                     cs.namespace(|| format!("multiply M[{}][{}] by inputs[{}]", j, i, j)),
//                     &inputs_j,
//                 )?;
//                 lc = lc.add(
//                     cs.namespace(|| format!("add lc to tmp[{}][{}]", j, i)),
//                     &tmp,
//                 )?;
//             }

//             self.outputs[i] = lc.get_value();
//         }

//         Ok(())
//     }
// }

// #[derive(Clone)]
// pub struct PoseidonCircuit<E: JubjubEngine> {
//     pub inputs: Vec<Option<E::Fs>>,
//     pub output: Option<E::Fs>,
//     pub width: usize,
// }

// impl<E: JubjubEngine> PoseidonCircuit<E> {
//     pub fn with_capacity(capacity: usize) -> Self {
//         Self {
//             inputs: vec![None; capacity - 1],
//             output: None,
//             width: capacity,
//         }
//     }

//     pub fn run<CS>(&mut self, mut cs: CS) -> Result<(), SynthesisError>
//     where
//         CS: ConstraintSystem<E>,
//     {
//         let input_num = self.width - 1;
//         assert_eq!(self.inputs.len(), input_num, "invalid inputs length");

//         // Using recommended parameters from whitepaper https://eprint.iacr.org/2019/458.pdf (table 2, table 8)
//         // Generated by https://extgit.iaik.tugraz.at/krypto/hadeshash/-/blob/master/code/calc_round_numbers.py
//         // And rounded up to nearest integer that divides by width
//         // let C: [E::Fr; T * (n_rounds_f + n_rounds_p)] = POSEIDON_C(T);
//         // let M: [[E::Fr; T]; T] = POSEIDON_M(T);

//         let mut ark: Vec<ArkCircuit<E>> = Vec::with_capacity(N_ROUNDS_F + N_ROUNDS_P - 1);
//         let mut sigma_f: Vec<Vec<SigmaCircuit<E>>> =
//             vec![Vec::with_capacity(self.width); N_ROUNDS_F - 1];
//         let mut sigma_p: Vec<SigmaCircuit<E>> = Vec::with_capacity(N_ROUNDS_P);
//         // let mut mix: Vec<MixCircuit<E>> = Vec::with_capacity(N_ROUNDS_F + N_ROUNDS_P - 1);
//         let mut last_mix: MixCircuit<E> = MixCircuit::with_capacity(self.width);

//         let mut wrapped_inputs = vec![];
//         for j in 0..input_num {
//             let input_j = AllocatedNum::alloc(
//                 cs.namespace(|| format!("allocate self.inputs[{}]", j)),
//                 || {
//                     Ok(self.inputs[j].unwrap())
//                     // self.inputs[j].ok_or(SynthesisError::UnconstrainedVariable)
//                 },
//             )?;
//             wrapped_inputs.push(input_j);
//         }

//         let zero = AllocatedNum::zero(cs.namespace(|| "allocate zero"))?;
//         for i in 0..(N_ROUNDS_F + N_ROUNDS_P - 1) {
//             ark.push(ArkCircuit::with_capacity(self.width, self.width * i));
//             for (j, ark_i_inputs_j) in ark[i].inputs.iter_mut().enumerate() {
//                 let tmp = if i == 0 {
//                     // ark[0].inputs[j] = j < input_num ? inputs[j] : 0;
//                     if j < input_num {
//                         wrapped_inputs[j].get_value()
//                     } else {
//                         zero.get_value()
//                     }
//                     // let input_j_or_zero = AllocatedNum::conditionally_select(
//                     //   cs.namespace(|| format!("select self.input[{}] if {} < input_num", j, j)),
//                     //   &wrapped_inputs[j],
//                     //   &zero,
//                     //   &Boolean::Constant(j < input_num),
//                     // )?;
//                     // input_j_or_zero.get_value()
//                 } else {
//                     // ark[i].inputs[j] = mix[i-1].outputs[j];
//                     let input_j = AllocatedNum::alloc(
//                         cs.namespace(|| format!("allocate mix[{}].outputs[{}]", i - 1, j)),
//                         || {
//                             Ok(last_mix.outputs[j].unwrap())
//                             // last_mix.outputs[j].ok_or(SynthesisError::UnconstrainedVariable)
//                         },
//                     )?;
//                     input_j.get_value()
//                 };
//                 let _ = std::mem::replace(ark_i_inputs_j, tmp);
//             }
//             ark[i].run(cs.namespace(|| format!("ark[{}]", i)))?;

//             last_mix = MixCircuit::with_capacity(self.width); // current_mix
//             if ((N_ROUNDS_F / 2)..(N_ROUNDS_F / 2 + N_ROUNDS_P)).contains(&i) {
//                 let k = i - N_ROUNDS_F / 2; // unnecessary
//                 let mut sigma_p_k = SigmaCircuit::default();
//                 sigma_p_k.input = ark[i].outputs[0];
//                 sigma_p_k
//                     .run(cs.namespace(|| format!("sigma_p[{}]", k)))
//                     .unwrap();
//                 last_mix.inputs[0] = sigma_p_k.output;
//                 sigma_p.push(sigma_p_k); // unnecessary
//                 for j in 1..T {
//                     last_mix.inputs[j] = ark[i].outputs[j];
//                 }
//             } else {
//                 let k = if i < N_ROUNDS_F / 2 {
//                     i
//                 } else {
//                     i - N_ROUNDS_P
//                 };
//                 for j in 0..self.width {
//                     let mut sigma_f_k_j = SigmaCircuit::default();
//                     sigma_f_k_j.input = ark[i].outputs[j];
//                     sigma_f_k_j
//                         .run(cs.namespace(|| format!("sigma_f[{}][{}]", k, j)))
//                         .unwrap();
//                     last_mix.inputs[j] = sigma_f_k_j.output;
//                     sigma_f[k].push(sigma_f_k_j); // unnecessary
//                 }
//             }
//             last_mix.run(cs.namespace(|| format!("mix[{}]", i)))?;
//         }

//         // last round is done only for the first word, so we do it manually to save constraints
//         let mut last_sigma_f = SigmaCircuit::default();
//         let c = read_field_element_be::<E::Fr>(
//             &hex::decode(&C[self.width * (N_ROUNDS_F + N_ROUNDS_P - 1)][2..]).unwrap(),
//         )
//         .unwrap();
//         let output_0 = AllocatedNum::alloc(
//             cs.namespace(|| format!("allocate mix[{}].outputs[0]", N_ROUNDS_F + N_ROUNDS_P - 1)),
//             || {
//                 Ok(last_mix.outputs[0].unwrap())
//                 // last_mix.outputs[0].ok_or(SynthesisError::UnconstrainedVariable)
//             },
//         )?;
//         let last_sigma_f_input = output_0.add_constant(cs.namespace(|| "add output_0 to c"), c)?;
//         last_sigma_f.input = last_sigma_f_input.get_value();
//         last_sigma_f.run(cs.namespace(|| "last_sigma_f"))?;
//         self.output = last_sigma_f.output;

//         Ok(())
//     }
// }
